# Import-explain cache sizing on a quiet host (October 2026)

> **Document class: HISTORICAL.** These measurements cover one source tree,
> two synthetic loopback fleet shapes, and one host. They are not a memory
> guarantee for another deployment, attribute mix, or allocator.

This receipt measures what the per-session import-explain cache costs a running
daemon at the shipped flat default and at two raised ceilings, after the cache
index became lazy and evicted prefixes started answering `evicted`. It supports
keeping the per-session explain cache default flat at 4,096, with explain still
opt-in. The rejected-route retention default of 1,024 was not exercised: every
cell rejected zero routes, so this receipt makes no claim about it.

At two peers announcing 1,000,000 IPv4 routes each, enabling the cache at the
4,096 default added **+40.5 MiB** of jemalloc-allocated memory and **+25.5 MiB**
of settled RSS against explain off. Its effect on the daemon cgroup peak was
inside the off arm's own 192 MiB repetition spread. Raising the ceiling to
262,144 or 1,048,576 added about **279 MiB** and **1.0 GiB** allocated. At
1,000 peers × 400 routes, single runs at 1,048,576 and 4,096 allocated within
0.5 MiB of each other. A large configured ceiling is not reserved per session.

## Shape and provenance

Source tree `6a22733879ccecb64c2b9e27dc799d3183549072` was built with Rust
1.99.0 (release daemon and CLI, `scale` harness profile) on Linux
7.0.0-30-generic, AMD Ryzen Threadripper 7970X, 64 online CPUs, jemalloc.
The binaries were identical in all ten cells. The driver is the unmodified
[`run-explain-cache-variant.sh`](run-explain-cache-variant.sh) with zero
reloads: the harness converges, holds the table without churn for a 10 s
control window, and waits while the runner captures settled metrics and two
import-explain answers before acknowledging the final evidence barrier.

| Arm | Peers × routes per peer | `[policy.explain]` | Repetitions |
|---|---|---|---:|
| A | 2 × 1,000,000 | `enabled = false` | 2 |
| B | 2 × 1,000,000 | `enabled = true`, `cache_size = 4096` | 2 |
| C | 2 × 1,000,000 | `enabled = true`, `cache_size = 262144` | 2 |
| D | 2 × 1,000,000 | `enabled = true`, `cache_size = 1048576` | 2 |
| E | 1,000 × 400 | `enabled = true`, `cache_size = 4096` | 1 |
| F | 1,000 × 400 | `enabled = true`, `cache_size = 1048576` | 1 |

The cells ran A, B, C, D, E, F, then A, B, C, D on 2026-10-07 between 20:28
and 20:39 UTC. All ten runner exits, harness exits, sampler exits, settled
metric gates, explain-evidence gates, and clean-tree checks passed. No cell was
retried or excluded. Every two-peer cell converged at 1,000,000 routes per
observer in 4.4–4.8 s. Every 1,000-peer cell converged in 4.0–4.3 s.

## Memory results

The primary measure is the kernel `memory.peak` of a cgroup containing only
the measured daemon. Each cell ran in a transient delegated scope with
`MemorySwapMax=0`. A small wrapper moved the daemon into its own leaf cgroup
as soon as it started, before any peer connected. The 5.0–5.2 MiB of
anonymous memory the two-peer daemons had touched before that move is not in
their cgroup peak. For 1,000-peer daemons the figure is 14.9–17.6 MiB. The
host has no swap device, and every cell recorded zero swap peak and zero OOM
events. Settled VmRSS, VmHWM and jemalloc gauges are the runner's own
secondary readings.

| Arm | Daemon cgroup peak (MiB) | VmHWM (MiB) | Settled VmRSS (MiB) | jemalloc allocated (MiB) |
|---|---:|---:|---:|---:|
| A off | 1,594.6 / 1,786.7 | 1,608.9 / 1,802.9 | 1,388.0 / 1,383.4 | 1,527.1 / 1,527.2 |
| B 4,096 | 1,686.8 / 1,698.1 | 1,693.5 / 1,705.3 | 1,412.1 / 1,410.3 | 1,567.8 / 1,567.7 |
| C 262,144 | 1,849.9 / 1,853.2 | 1,859.7 / 1,865.6 | 1,645.7 / 1,647.7 | 1,806.2 / 1,806.3 |
| D 1,048,576 | 2,570.0 / 2,574.0 | 2,582.9 / 2,583.4 | 2,368.1 / 2,364.6 | 2,526.2 / 2,526.0 |
| E 1,000 × 400, 4,096 | 648.6 | 666.7 | 666.7 | 553.2 |
| F 1,000 × 400, 1,048,576 | 640.8 | 655.4 | 654.4 | 553.7 |

Arm means minus explain off, two peers × 1,000,000 routes:

| Arm | Cgroup peak | VmHWM | Settled VmRSS | jemalloc allocated |
|---|---:|---:|---:|---:|
| B 4,096 | +1.8 MiB | −6.5 MiB | +25.5 MiB | +40.5 MiB |
| C 262,144 | +160.9 MiB | +156.7 MiB | +261.0 MiB | +279.1 MiB |
| D 1,048,576 | +881.4 MiB | +877.3 MiB | +980.7 MiB | +998.9 MiB |

The two explain-off repetitions settled within 5 MiB and allocated identical
amounts, but their transient ingest peaks differed by 192 MiB. Every enabled
arm repeated within 12 MiB. The peak therefore cannot resolve the default
4,096 cost at this shape; the settled and allocated readings do. The C and D
peak differences are smaller than their settled differences. This receipt does
not attribute that gap.

The allocated differences match the documented budget model. Two sessions at
4,096 retain 8,192 decisions and remember 1,991,808 evicted keys. At about
600 B per retained decision and 19 B per evicted key, that predicts about
40.8 MiB, against +40.5 MiB measured. D retains all 2,000,000 decisions with
no evictions, about 524 B allocated per decision. The configuration budget's
~600 B per retained decision is a conservative figure for this attribute shape.

The 1,000-peer pair addresses the former eager index. Each session held
400 decisions under either ceiling. Raising the ceiling from 4,096 to
1,048,576 moved allocated memory by +0.5 MiB and the cgroup peak by −7.8 MiB.
These are single-run observations per arm, so they carry no repetition spread.
The near-identical allocated totals still show that the ceiling is not
reserved up front: the eager design would have reserved an index for each
session sized to the full ceiling.

## Explain answers and completeness

Each cell queried peer `127.1.0.1` for its first-announced and last-announced
prefix before acknowledging the final barrier. Every answer matched the
runner's source-derived expectation, including the capacity and eviction
count fields:

| Arm | First prefix | Last prefix | Reported `cache_size` | Reported `evictions_since_reset` |
|---|---|---|---:|---:|
| A off | `cache_disabled`, exit 1 | `cache_disabled`, exit 1 | null | null |
| B 4,096 | `evicted` | `permit` | 4,096 | 995,904 |
| C 262,144 | `evicted` | `permit` | 262,144 | 737,856 |
| D 1,048,576 | `permit` | `permit` | 1,048,576 | 0 |
| E, F | `permit` | `permit` | 4,096 / 1,048,576 | 0 |

At the flat default, a full-table peer's early prefixes report `evicted` with
an exact eviction count. They are not reported as `not_seen`. A truncated
answer is therefore visible to the operator rather than silently presented as
complete.

## Decision

This receipt supports keeping the explain cache default flat at 4,096 and
explain opt-in. At the 4,096 default, explain on a 1,000,000-route peer costs about 20 MiB, mostly
evicted-key memory that the reply reports. Retaining a full table costs
roughly 0.5 GiB per 1,000,000-route peer at this attribute shape. Operators
who need that coverage can raise the global ceiling deliberately and budget
for it. A large ceiling no longer costs anything on small peers. Nothing here
argues for derived sizing or a larger default. The rejected-route retention
default was not exercised: every cell rejected zero routes.

## Limitations

- One host, one allocator, loopback, synthetic IPv4 /24 routes with the
  generator's attribute shape. Per-decision cost moves with attributes.
- Two repetitions per two-peer arm and one per 1,000-peer arm. The explain-off
  peak spread shows a single transient peak can move by about 190 MiB at this
  shape.
- The cgroup peak omits the 5.0–17.6 MiB the daemon touched before the
  wrapper moved it. That omission applies equally to every cell of a shape.
- No throughput, convergence, reload, churn, Add-Path, IPv6, or explain-query
  latency claim is made. The 1,000-peer cells exercise a 400-route table, not
  saturated caches.

## Artifacts

The [compact artifact set](artifacts/explain-cache-quiet-host-2026-10/README.md)
holds per-cell readings, every explain answer, the recompute script and its
output, the cgroup wrapper, the campaign driver and provenance.
