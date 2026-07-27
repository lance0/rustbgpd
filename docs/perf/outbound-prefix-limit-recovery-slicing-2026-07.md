# Outbound prefix-limit recovery slicing receipt — 2026-07

This receipt measures the bounded-work recovery path for grouped outbound
prefix limits. It is an availability change: it returns the single-owner RIB
actor between peer/family replays. It does **not** reduce the total full-table
replay work required to refill every member after a limit is removed.

## Pinned path and shape

The release daemon and standalone TCP BGP driver were built from
`727b366583fb24a68fad6075cfbb78c7ff18fe4b`. Each cell used one private source,
400,000 unique IPv4 unicast `/32`s, and 1, 10, or 100 homogeneous members in
exactly one update group. The source was the only fallback peer and no session
negotiated Add-Path. Candidate cells installed
`max_prefixes_out_ipv4 = 400000`, received 64 further source routes while
blocked, then removed the limit. Controls used the identical SHA, daemon,
fleet, and table but stayed unlimited through the reloads.

This is a six-cell same-SHA **configuration** campaign, not a code A/B or a
statistical variance estimate. Its controls bound unrelated reload and
allocator movement in the run. The retained pre-slicing scale receipt used a
different immediate-parent revision and remains the one-shot comparison, not a
same-SHA performance control.

## Correctness receipt

All six cells passed: 69 and 71 checks at one member, 429 and 431 at ten, and
4,029 and 4,031 at 100 (control/candidate respectively), with zero failures. The
harness verified one exact update group of the requested membership, an
Established session and valid decoded UPDATEs for every member, 400,000
admitted identities per candidate member, exactly 64 withheld routes per
candidate member, and all 400,064 routes delivered after the limit removal.
It also verified the finite limit and blocking metrics, the recovery metric,
and that neither limit-only reload changed the session or group.

Candidate recovery emitted exactly one production recovery histogram sample
per member: 1, 10, and 100 samples at the three fleet sizes. Controls emitted
none. Each candidate's slowest individual slice landed in the `(0.2, 0.5]`
second histogram bucket.

## Result and boundary

| Members | Candidate recovery samples | Total recovery actor work | Candidate recovery wall time | Slowest slice bucket |
|---:|---:|---:|---:|---|
| 1 | 1 | 0.274244704 s | 1.401008763 s | (0.2, 0.5] s |
| 10 | 10 | 2.755427506 s | 3.941656727 s | (0.2, 0.5] s |
| 100 | 100 | 27.064279369 s | 29.283564918 s | (0.2, 0.5] s |

At 100 members, recovery therefore becomes 100 bounded actor turns rather
than one long actor turn. The sum of those turns is 27.064279369 seconds and
the end-to-end recovery wall time is 29.283564918 seconds. The retained
immediate-parent, pre-slicing one-shot receipt recorded approximately 27.854
seconds for the same 100-member full-table recovery shape. The difference
between those separate single runs is not a total-work improvement claim:
this change is specifically actor-occupancy and latency isolation, with a
small amount of additional wall-clock scheduling time expected between slices.

The campaign does not establish run-to-run variance, a full-tail latency
distribution inside the Prometheus histogram bucket, a larger-fleet
extrapolation, or a reduction in route evaluation/encoding work. It also does
not make a claim about the controls' `recovery_wall_seconds`: without a
candidate recovery, that value is only the harness's completion observation.

## Reproduction and artifacts

Run the host-locked real-daemon campaign:

```text
bench/scale/outbound-prefix-limit-scale/run-receipt.sh
```

Raw output remains private under `target/outbound-prefix-limit-scale/`.
The compact sanitized campaign, provenance, binary identities, and checksums
are retained in
[`artifacts/outbound-prefix-limit-recovery-slicing-2026-07/`](artifacts/outbound-prefix-limit-recovery-slicing-2026-07/README.md).
The earlier admitted-set memory/one-shot recovery scale result remains in
[`outbound-prefix-limit-scale-2026-07.md`](outbound-prefix-limit-scale-2026-07.md).
