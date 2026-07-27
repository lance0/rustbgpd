# Grouped outbound prefix-limit scale receipt — 2026-07

ADR-0113 keeps one exact admitted-prefix set per limited peer and family, even
when the peers share an update group. This receipt measures the cost of
installing and removing those sets before changing their representation.

## Pinned path and fleet

The real release daemon and standalone TCP BGP driver were built from commit
`8543c7922d8e96b0e64457acf6e152d6666118fc` (tree
`db010813aadf89674d0502659c2a823c2027e01a`), whose production base is main at
`870062f0`. The measured commit adds only the receipt harness.

Every cell used one private route-server-client source, 400,000 unique IPv4
unicast `/32`s, and 1, 10, or 100 homogeneous route-server-client members in
exactly one update group. The source was the only fallback peer. No session
negotiated Add-Path. The control and candidate used the same SHA, daemon,
commands, table, and fleet. Both began unlimited; the control stayed unlimited
through both reloads while the candidate installed
`max_prefixes_out_ipv4 = 400000`, received 64 more source routes while
blocking, and then removed the limit.

The pair order alternated to avoid a fixed ordering bias: control then
candidate at 1 member, candidate then control at 10, and control then candidate
at 100. The run used the release profile with jemalloc on Linux
6.17.0-35-generic, an AMD Ryzen Threadripper 7970X 32-Core CPU, rustc 1.97.0,
and LLVM 22.1.6.

## Correctness receipt

All six cells passed. At every phase:

- there was exactly one update group with exactly the requested members and
  the source alone on the fallback path;
- every member remained Established and every decoded UPDATE was valid;
- the control delivered all 400,064 prefixes to every member;
- the candidate installed exactly 400,000 admitted identities per member,
  withheld exactly 64 routes per member, and reported the finite limit,
  blocking latch, and 64 blocked attempts on the production metrics;
- removing the candidate limit delivered all 400,064 prefixes to every member;
- each reload contributed exactly one production `apply` histogram sample,
  and only the candidate removal contributed one `recovery` sample.

The cells performed 69, 70, 429, 430, 4,029, and 4,030 assertions respectively,
with zero failures. No limit-only reload deleted a peer.

## Result

The paired deltas subtract each unlimited control's apply delta from the
adjacent candidate's apply delta.

| Members | Control apply | Candidate apply | Paired actor delta | Paired allocated delta | Allocated per member | Paired RSS delta | Candidate recovery actor time |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.008 ms | 20.658 ms | 20.650 ms | 9,881,808 B | 9,881,808 B | 13,500 KiB | 0.291 s |
| 10 | 0.023 ms | 208.677 ms | 208.654 ms | 99,197,120 B | 9,919,712 B | 96,644 KiB | 2.803 s |
| 100 | 0.152 ms | 2,050.572 ms | 2,050.420 ms | 996,385,552 B | 9,963,856 B | 965,292 KiB | 27.854 s |

The admitted sets therefore retain about 9.9 MB per member at this 400,000
route shape. The 100-member candidate raised live jemalloc allocation from
342,623,488 to 1,339,691,632 bytes and point RSS from 372,732 to
1,332,996 KiB. After removal and recovery, live allocation returned to
343,465,280 bytes, 841,792 bytes above its baseline.

The production actor durations scale closely with member count across the
three observed points: about 20.5–20.9 ms per member to materialize the sets
and about 279–291 ms per member to recover the full table. Recovery is the
larger operational concern because it occupies the single RIB actor while
re-evaluating and queuing the previously withheld family.

## Variance and limits

This is one fixed six-cell campaign, not a repeated statistical sample, so it
does not estimate run-to-run variance. The same-SHA controls bound unrelated
apply work and allocator drift in this run: their apply allocation deltas were
121,416, 510,056, and 682,592 bytes, while point RSS moved by -6,092, -2,108,
and -5,028 KiB. Paired subtraction is used above; absolute control and
candidate baselines are retained in the artifacts.

The one-second RSS sampler observed the kernel `VmHWM` value decrease during
the busiest 100-member candidate phase, from 1,332,996 to 1,325,096 KiB.
Consequently this receipt uses the maximum across all sampler rows as the
process high-water observation rather than assuming a later `/proc` snapshot
must preserve the maximum.

The measured range stops at 100 members and 400,000 IPv4 routes. The near
linear points do not license a 1,000-member, one-million-route extrapolation.
They are sufficient to reject the current representation as cheap at the
measured route-server shape and to require a controlled representation or
recovery experiment before claiming larger-fleet headroom.

## Reproduce, artifacts, and red proofs

Run the host-locked campaign:

```text
bench/scale/outbound-prefix-limit-scale/run-receipt.sh
```

It takes no shape arguments, refuses a dirty tree or a busy host, builds the
real release daemon and driver, and keeps raw path-bearing output private under
`target/outbound-prefix-limit-scale/`. Compact sanitized evidence is retained
under
[`artifacts/outbound-prefix-limit-scale-2026-07/`](artifacts/outbound-prefix-limit-scale-2026-07/README.md).

The fixed-shape, real encoding, unique-prefix bitmap, exact metric parser, and
`VmRSS`/`VmHWM` distinction each have an executed destructive proof recorded in
the harness. The live campaign goes red if cap installation, admission,
single-group membership, every-member delivery, recovery scheduling, real wire
decode, allocator metrics, or session continuity is removed.
