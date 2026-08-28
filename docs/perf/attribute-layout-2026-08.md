# Interned attribute-container layout receipt (August 2026)

Status: completed negative evidence campaign; no production representation
change.

## Question

Routes currently hold `Arc<Vec<PathAttribute>>`. Replacing it with
`Arc<[PathAttribute]>` removes one Vec header and one allocation per unique
interned attribute set, but a slice Arc is a fat pointer. The wider pointer is
paid by every stored Route copy, while the Vec saving is paid only once per
unique set. This campaign measures that trade rather than assuming the slice
form is smaller.

The common inbound path also rebuilds canonical stored attributes after
removing `MP_REACH_NLRI` and `MP_UNREACH_NLRI`. Decode-time Vec spare capacity
therefore is not counted as a persistent stored-route saving.

## Structural model

For a shape with `R` stored Route copies and `U` unique interned sets:

```text
modeled_delta = R * (sizeof(Arc<[T]>) - sizeof(Arc<Vec<T>>))
              - U * sizeof(Vec<T>)
```

Positive is larger for the slice form. The model intentionally excludes
allocator size classes, per-allocation metadata, locality, conversion cost,
and nested attribute payloads. Those are measured separately; a negative model
is necessary but not sufficient evidence for a production change.

On a 64-bit target the expected terms are an 8-byte wider pointer and a
24-byte Vec header. The break-even point is therefore one unique set per three
Route copies. A full-RIB row stores three copies per prefix and the fanout row
stores five.

The calibrated arm uses one unique set per seven prefixes. This is slightly
more diverse—and therefore slightly more favorable to the slice hypothesis—
than the observed IPv4 sample of 146,981 interned sets for 1,081,298 prefixes
(about one per 7.36 prefixes). Before allocator effects, the expected delta is
about +20.6 B/prefix for full RIB and +36.6 B/prefix for RR fanout.

## Shapes and ownership

The structural harness keeps all prior bounds and adds:

- `full_rib_representative`: two Adj-RIB-In copies plus one Loc-RIB copy, with
  one cross-peer-identical attribute set per seven prefixes;
- `rr_fanout_representative`: the same inputs and Loc-RIB plus two Adj-RIB-Out
  copies, preserving the same set ratio.

`full_rib` and `rr_fanout` remain low-diversity bounds;
`full_rib_diverse` remains the one-set-per-prefix upper bound. Every JSONL row
records the thin/fat pointer sizes, Vec header size, six route-family sizes,
MP payload/boxed-pointer sizes, unique-set count, Route-copy count, pointer
growth, Vec-header saving, modeled delta, and break-even set count.

DHAT classification splits the stored outer attribute vector from nested
`AS_PATH`/community payload allocations. The ordinary 2-peer x 100k bgperf2
run is retained for ownership attribution, but its deliberately low attribute
diversity is not the migration gate.

## Preregistered gate

A later production prototype is authorized only if all of these hold:

1. the 900k `full_rib_representative` row saves more than both 5% and 50 MiB;
2. neither degenerate nor fanout bounds reaches the existing +5% and +32 MiB
   review threshold;
3. the calibrated set ratio is exactly the ceiling of prefixes divided by 7;
4. RIB operations, inbound attribute handling, export fanout, and rrharness
   throughput remain neutral under their existing campaign rules; and
5. process-level movement clears the documented allocator noise band.

Failure of any gate rejects the `Arc<[PathAttribute]>` migration. It does not
authorize a different wire-layout change. Public `PathAttribute` payload or
enum changes require a separately planned compatibility release.

## Commands

Cheap schema and classifier proof:

```text
cargo test -p rustbgpd-rib --features bench-internals \
  --test memory_profile memory_profile_schema_quick
python3 bench/scale/rebaseline/test_classifiers.py
```

Resource-exclusive structural campaign, from a clean committed source SHA:

```text
bench/compare-rib-memory.sh \
  --base origin/main \
  --head HEAD \
  --profile full
```

The measured section records the exact harness commit, quiet-host/lock
preconditions, output checksums, all structural rows, and the sanitized DHAT
derivative. Raw DHAT JSON, host paths, process IDs, and mutable image tags do
not enter the repository.

## Measured result

**Rejected.** The full structural campaign measured harness revision
`73380e1cdc0519a4af5b4c3559bb4922b14582f7` against
`f822fd2ba407117dcf8a6d7faa32018b77dae250`. At 900,000 prefixes and the
calibrated one-set-per-seven ratio, the full-RIB shape has 2,700,000 Route
copies and 128,572 attribute sets. A slice Arc adds 20.6 MiB of pointer storage
and removes 2.9 MiB of Vec headers: a net **17.7 MiB increase**. The
route-reflector fanout shape has 4,500,000 Route copies at the same set count,
for a net **31.4 MiB increase**. Even the deliberately favorable full-RIB
bound of one unique set per prefix only breaks even before allocator overhead.

The baseline revision predates the two representative rows, so their observed
live-byte columns are intentionally absent rather than presented as an A/B.
The rejection comes from compiler-reported 64-bit pointer/header sizes and the
exact Route-copy/set counts. Every pre-existing shape was byte-identical
between revisions, confirming that the evidence-only harness changed no
production representation.

The structural run held the shared benchmark mutex and began at a one-minute
load of 1.91. A separate production-daemon DHAT attribution reran from the
same source at 2026-08-28T02:36:38Z with load `0.04 0.66 1.56`, bgperf2
revision `ad8a7deba21e8ffa1aed609b86e0d0236b0489cd`, and immutable image digest
`sha256:7411c6562dacc4ec1c6153562bed9a087d47d8a387f6713c14d3347feb69db6a`.
It converged 200,000 of 200,000 routes with zero tester errors/timeouts and
classified 163,438,128 live bytes. The low-diversity fixture attributed zero
live bytes to the outer interned attribute backing and 792 bytes to nested
payloads, which is useful ownership evidence but, as preregistered, is not the
migration gate.

No production prototype or throughput campaign is warranted: the necessary
structural gate fails in the wrong direction. The sanitized rows, bounded DHAT
derivative, structural matrix, provenance, and checksums are retained in the
[`attribute-layout-2026-08` artifacts](artifacts/attribute-layout-2026-08/README.md).
