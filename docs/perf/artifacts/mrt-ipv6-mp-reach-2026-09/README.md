# MRT IPv6 snapshot shape and stack-built MP_REACH (2026-09)

This receipt measures the MRT snapshot encoder building the reduced
`MP_REACH_NLRI` next-hop attribute on the stack instead of allocating a
33-byte `Vec` per route. That attribute is written for every IPv6 route and
every IPv4 route with an IPv6 next hop.

Neither existing `snapshot_allocation` shape exercised that path, because both
are IPv4-only with IPv4 next hops. This change adds an `ipv6-full-feed` shape:

- 400,400 IPv6 `/64` prefixes from 2 sources, 800,800 paths;
- each source has a global IPv6 next hop;
- the second source's routes also carry a link-local next hop, which exercises
  the 32-byte form.

The shape also makes IPv6 MRT dump cost measurable for the first time.

## Arms

| Arm | Commit | Tree |
| --- | --- | --- |
| `control` | `6ee25355a86b566afc7fb8be12ae06e7d8901c13` | main `660a2388a` plus the new shape (instrument only) |
| `scratch` | `831ecfb10e8b77a338ee26de6f045cb3eb54595b` | the reused attribute buffer (see [`mrt-attribute-scratch-2026-09`](../mrt-attribute-scratch-2026-09/README.md)) plus the new shape |
| `candidate` | `8005159f84ba4f07d2e34d0fad41d08da7356330` | `scratch` plus the stack-built `MP_REACH_NLRI` |

These are the measured pre-rebase commits. The `scratch` change later
landed on main as `f77656f92`. After rebasing onto it, the shape and
stack-buffer changes are the commits titled `test(mrt): add an ipv6 snapshot
allocation shape` and `perf(mrt): build the reduced mp_reach attribute on the
stack`, with identical source. The control commit exists only
locally; it is main `660a2388a` with this branch's `snapshot_allocation.rs`.
All three arms run the identical instrument source.

## Commands

```sh
cargo build --locked --profile bench -p rustbgpd-mrt --bench snapshot_allocation
cargo build --locked --profile bench -p rustbgpd-mrt --bench snapshot_allocation \
  --features snapshot-allocation-diagnostics

# One diagnostic run per arm and shape, at fixed originated time.
snapshot_allocation diagnostic --candidate --shape <shape> --commit <sha> --output <file>

# Timing on one pinned core; each run takes 2 warmups and 7 samples.
taskset -c <core> snapshot_allocation timing --candidate --shape <shape> --commit <sha> --output <file>
```

- **Three-arm run:** 4 blocks in control, scratch, candidate, candidate,
  scratch, control order, all three shapes.
- **Confirmation run:** 6 blocks in scratch, candidate, candidate, scratch
  order, `ipv6-full-feed` only.

## Recorded fields

The instrument writes one JSON object per sample (`schema_version` 2) with
these fields: `schema_version`, `variant`, `commit`, `mode`, `shape`, `smoke`,
`warmup_count`, `sample_index`, `path_count`, `prefix_count`, `source_count`,
`output_len_bytes`, `output_capacity_bytes`, `decoded_entry_count`,
`elapsed_ns`, `raw_sha256`, `semantic_sha256`, `allocator`, `growth` and
`growth_path_assertion`.

Every arm ran with `--candidate`, so every row records `"variant":"candidate"`.
That flag selects the instrument's bounded top-level growth assertion, which
all arms satisfy; it does not identify the arm. **The arm is identified by
`commit`** (see the table above).

The committed files are the instrument's rows, post-processed as follows.
Every instrument field and value is unchanged:

- **`timing.jsonl`:** the 72 three-arm run files, concatenated in execution
  order. Added fields:
  - `campaign`: `three-arm`;
  - `run_order`: position in execution order;
  - `block`: the ABBA block;
  - `arm`: derived from `commit`.
- **`timing-confirm.jsonl`:** the 24 confirmation run files, handled the same
  way, with `campaign` set to `ipv6-confirm`.
- **`diagnostic.jsonl`:** the nine diagnostic files (control, scratch,
  candidate; each `ixp-700`, `dual-full-feed`, `ipv6-full-feed`),
  concatenated. An `arm` field derived from `commit` was added to each row.
- Rows were rewritten with sorted keys and compact separators.

## Results

**Allocator activity** (`diagnostic.jsonl`):

| Shape | Counter | Control | Scratch | Candidate | Candidate vs scratch |
| --- | --- | ---: | ---: | ---: | ---: |
| `ipv6-full-feed` | alloc calls | 8,808,806 | 4,804,807 | 4,004,007 | −16.667% (−800,800) |
| `ipv6-full-feed` | realloc calls | 2,402,444 | 1,601,645 | 1,601,645 | 0 |
| `ipv6-full-feed` | requested bytes | 628,696,446 | 579,847,675 | 553,421,275 | −4.557% |
| `ixp-700` | alloc calls | 4,804,807 | 2,402,408 | 2,402,408 | 0 |
| `dual-full-feed` | alloc calls | 9,609,606 | 4,804,807 | 4,804,807 | 0 |

Against control, the candidate has 54.545% fewer allocation calls on
`ipv6-full-feed`. Peak live requested bytes stay within 4 B of control on
every shape. The IPv4 shapes never reach the changed code, so their candidate
and scratch counts are identical.

**Output identity:** at fixed originated time, `raw_sha256` and
`semantic_sha256` are identical across all three arms for every shape. In the
timing files, the semantic hash, output length and decoded entry count are
identical across every sample of each shape.

**Elapsed time**, median of per-run medians:

| Shape | Control | Scratch | Candidate | Candidate vs control | Candidate vs scratch (per block) |
| --- | ---: | ---: | ---: | ---: | --- |
| `ipv6-full-feed` | 255.4 ms | 221.9 ms | 214.4 ms | −16.03% | −3.36% (−4.0, −2.4, −5.4, −3.4) |
| `ipv6-full-feed` (confirmation) | | 222.6 ms | 215.4 ms | | −3.21% (−3.1, −1.9, −0.4, −3.5, −5.0, −3.7) |
| `dual-full-feed` | 254.6 ms | 219.1 ms | 217.7 ms | −14.49% | −0.64% (−1.5, −0.1, +0.9, −1.0) |
| `ixp-700` | 140.7 ms | 123.3 ms | 123.5 ms | −12.18% | +0.20% (−0.8, +0.8, +4.2, −0.3) |

- The three-arm run has 8 runs per arm and shape; the confirmation has 12.
- The maximum within-run coefficient of variation is 3.92% (three-arm) and
  5.31% (confirmation).
- The stack-built attribute is slower in none of the 10 `ipv6-full-feed`
  blocks. The IPv4 shapes, which do not run it, move within ±1.5% except one
  +4.2% block.

These are encoder-only measurements of the snapshot builder, not daemon dump
wall time.
