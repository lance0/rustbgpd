# outbound-prefix-limit-scale

Measurement-first scale harness for ADR-0113's per-member grouped outbound
prefix admission sets.

## Question

At a route-server table and fanout shape, how much live memory and synchronous
RIB-actor time does first cap installation consume, and how expensive is the
recovery scan when removing that cap?

This harness does not contain an optimization. It measures the shipped design
before any design decision is made.

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
| Variants | unlimited same-SHA control; limited candidate |

Both variants converge the 400,000-prefix table while unlimited. A SIGHUP then
drives the production outbound-prefix-limit Prepare/Apply transaction in both
variants. The control remains unlimited; the candidate installs
`max_prefixes_out_ipv4 = 400000`, which materializes the grouped admitted set
for every member.

The source next announces 64 more prefixes. Every control member must receive
them. Every candidate member must remain at 400,000, report 64 blocked
attempts, and retain the one shared update group. A final SIGHUP keeps the
control unlimited and removes the candidate cap. Every candidate member must
then receive all 64 withheld prefixes.

The control is a same-command-shape control, not merely a settled-RSS baseline:
the SIGHUP path unconditionally calls `apply_outbound_prefix_limits`, which
sends `PrepareOutboundPrefixLimits` and `ApplyOutboundPrefixLimits`; the RIB
actor records one `apply` histogram sample even when every resolved limit
remains absent. The candidate's additional work is the per-member set
materialization.

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
requires exactly one sample per grouped member, matching the bounded
peer/family actor slices. The `_sum` delta is therefore total synchronous
actor work, while the cumulative bucket deltas bound the slowest individual
slice. The receipt separately measures operator-visible recovery wall time
from the recovery SIGHUP until every member has the withheld tail. A later
`/proc` `VmHWM` snapshot is not assumed to preserve an earlier maximum:
concurrent accounting was observed to lower it during the 100-member
campaign. The published high-water observation is therefore the maximum
across the independent sampler rows. `VmRSS` remains a point-in-time value.

## Run

The driver is intentionally fixed-shape and takes no arguments:

```text
bench/scale/outbound-prefix-limit-scale/run-receipt.sh
```

It refuses a dirty tree, acquires the shared host lock, requires an idle
performance-governor host with at least 16 GiB available, builds the real
daemon and harness, and alternates control/candidate order across the three
fleet sizes. A failed preflight aborts the campaign; the driver never silently
shrinks the table or fleet.

Raw, path-bearing output stays private under
`target/outbound-prefix-limit-scale/`. Only a separately reviewed sanitized
summary is suitable for committing.

## Load-bearing red proofs

The campaign assertions are deliberately structural:

- removing cap installation makes the candidate finite-limit rows red;
- bypassing admission makes every candidate withheld wire-count check red;
- splitting a member to a private path or another group makes the exact
  group-id/member inventory red;
- suppressing recovery scheduling makes both the exact one-sample-per-member
  recovery histogram delta and every member's final wire count red;
- collapsing the bounded slices back into one actor turn makes the recovery
  sample-count assertion red;
- replacing the production transaction with a no-op makes the histogram count
  delta red in both variants;
- parsing `VmRSS` as `VmHWM` makes the strict parser fixture red.

No performance result is accepted from a run that fails any behavior or path
assertion.
