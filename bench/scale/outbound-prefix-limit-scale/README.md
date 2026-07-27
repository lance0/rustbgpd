# outbound-prefix-limit-scale

Immutable immediate-parent A/B scale harness for ADR-0113's per-member grouped
outbound prefix admission sets.

## Question

At a route-server table and fanout shape, does the current commit use at most
half the additional live allocated memory its literal parent used to
materialize the same admitted sets?

RSS and apply/recovery time are retained for diagnosis, but do not gate the
result.

## Fixed campaign

Each cell runs a real release-build `rustbgpd`, one real private
route-server-client source, and `N` real homogeneous grouped
route-server-client members:

| dimension | values |
|---|---|
| Grouped members | 1, 10, 100 |
| Initial table | 400,000 IPv4 `/32`s |
| Withheld tail | 64 additional IPv4 `/32`s |
| Add-Path | not negotiated |
| Update groups | exactly one, containing exactly the `N` members |
| Variants | literal first parent; current candidate |

Both source variants converge the 400,000-prefix table while unlimited. A
SIGHUP then drives the production outbound-prefix-limit Prepare/Apply
transaction and installs `max_prefixes_out_ipv4 = 400000`, which materializes
the grouped admitted set for every member.

The source next announces 64 more prefixes. Every member of both variants must
remain at 400,000, report exactly 64 blocked attempts, and retain the one
shared update group. A final SIGHUP removes the cap. Every member must then
receive all 64 withheld prefixes and reach exactly 400,064, with zero session
flaps, withdrawals, unexpected NLRI, or decode errors.

The driver refuses to run unless `HEAD^` is the candidate's literal first
parent and the benchmark subtree has the same Git tree object in both commits.
It builds each daemon from a detached worktree, records each source commit,
source tree, and binary digest, and builds the shared harness from the
candidate's identical benchmark tree.

## Measurement surfaces

Every phase retains:

- `jemalloc_allocated_bytes`, `active`, `resident`, and `mapped` from the
  shipped daemon's scrape;
- the daemon's kernel `VmRSS`, `VmSize`, and `VmHWM`, plus an independent
  one-second maximum across the scenario;
- the production
  `bgp_rib_outbound_prefix_limit_actor_duration_seconds{operation}` count and
  sum;
- update-group count, member count, and every peer's group id;
- every member's wire-side unique-prefix count and outbound-capacity gauges.

The apply gates require exactly one new histogram sample. Capacity recovery
requires exactly `N` samples, one per grouped member, matching the bounded
peer/family actor slices. The `_sum` delta is therefore total synchronous
actor work, while the cumulative bucket deltas bound the slowest individual
slice. The receipt separately measures operator-visible recovery wall time
from the recovery SIGHUP until every member has the withheld tail.
Zero sum deltas remain report-only numeric zero; non-finite deltas are
retained as `null`. If a slice exceeds the largest finite histogram boundary,
the lower boundary is reported and the upper boundary is `null` (the
Prometheus `+Inf` bucket); neither condition rejects an otherwise exact run.

For each fleet size, the acceptance gate is:

```text
candidate apply allocated delta <= 50% of parent apply allocated delta
```

The allocated delta is the change in production
`jemalloc_allocated_bytes` from the settled unlimited baseline to the settled
finite-limit snapshot. The receipt reports point RSS, sampled RSS/HWM, and
apply/recovery timing for both variants, but never accepts or rejects a run
from those report-only values.

## Run

The driver is intentionally fixed-shape and takes no arguments:

```text
bench/scale/outbound-prefix-limit-scale/run-receipt.sh
```

It refuses a dirty tree or a changed parent/candidate harness, acquires the
shared host lock, requires an idle performance-governor host with at least 16
GiB available, builds both real daemons and the shared harness, and alternates
parent/candidate order across the three fleet sizes. A failed preflight aborts
the campaign; the driver never silently shrinks the table or fleet.

Raw, path-bearing output stays private under
`target/outbound-prefix-limit-scale/`. Only a separately reviewed sanitized
summary is suitable for committing.

## Load-bearing red proofs

The campaign assertions are deliberately structural:

- removing cap installation makes the finite-limit rows red;
- bypassing admission makes every parent/candidate withheld wire-count check red;
- splitting a member to a private path or another group makes the exact
  group-id/member inventory red;
- suppressing recovery scheduling makes both the exact one-sample-per-member
  recovery histogram delta and every member's final wire count red;
- collapsing the bounded slices back into one actor turn makes the recovery
  sample-count assertion red;
- comparing any commit other than the literal parent, or changing the harness
  in the optimization commit, makes provenance red before builds start;
- retaining more than half the parent's allocated materialization delta makes
  the campaign aggregator red;
- parsing `VmRSS` as `VmHWM` makes the strict parser fixture red.

No performance result is accepted from a run that fails any behavior or path
assertion.
