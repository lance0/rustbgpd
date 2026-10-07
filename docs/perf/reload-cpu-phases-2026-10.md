# Daemon CPU variation across S2 reload process legs

The retained October 2026 S2 traces place most same-binary CPU variation outside
reload windows, but do not identify its cause.

This is an offline follow-up to the [export-probe delta receipt](export-probe-delta-arcvec-2026-10.md),
measured 2026-10-06: 700 peers, 400,400 prefixes, four reloads per process,
three launches per arm in ABBAAB order. It uses every original leg and reload.
No new benchmark, profiler, daemon run, or environmental experiment was performed.
The original receipt and its timing acceptance remain unchanged.

## Available evidence

All 298 files in the retained raw directory matched the original
[raw-file inventory](artifacts/export-probe-delta-arcvec-2026-10/archived-raw-sha256.json).
The retained tar archive also matched its recorded SHA-256
`ab44a1dff771a655bfa941bc6b2b7ecd4ac12acfdf27eaa0072c6898524cf456`.
These identify the historical inputs; they are not requirements on current source.
The archive remains unpublished. The public endpoint extracts below support the
partition arithmetic but cannot independently establish omitted trace contents.

The original [producer records](artifacts/export-probe-delta-arcvec-2026-10/provenance.json)
bind baseline A to `19842a5a114287af7a8f5ae66407aaacc9d0142a` and candidate B to
`3cf0dc277dc2f729d01e40207fbdab2d2e5fda11`. All A legs use daemon SHA-256
`67ae6325f4392a23ab0c6fbb51b1ed61a25b0caa4d3391224864f278480f93df`;
all B legs use `dd27aab2cb5246fb535340f9a6f4333245776b2ba78fc3ed034d44b423272d87`.
Both arms use the same baseline harness. In particular, **05-A is the same
executable as 01-A and 04-A**.

The sampler retains process CPU, summed task context switches, thread counts,
thread-read races, and process/cgroup memory. It does not retain per-thread CPU,
task identities or names, CPU/core placement, NUMA placement, THP counters,
khugepaged activity, jemalloc background-thread accounting, or timer slack.
Reading thread status before summing it does not preserve thread attribution.

## CPU partition

The nine disjoint intervals per leg reuse the exact sample endpoints in the
original [24 reload brackets](artifacts/export-probe-delta-arcvec-2026-10/cpu-brackets.csv):
before reload 1, each of four reload windows, three intervening gaps, and after
reload 4. Each reload window encloses its SIGHUP and worst observer completion,
including the original leading/trailing sampling uncertainty. The nine intervals
sum to first-to-last sampled CPU, not complete process lifetime CPU.

All values below are CPU-seconds. “Three gaps” sums the intervals between
successive reload brackets. “First 10 s” is an overlapping diagnostic slice,
excluded from the partition total.

| Leg | Sampled total | Before reload 1 | Four reload windows | Three gaps | After reload 4 | First 10 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 01-A | 86.76 | 27.65 | 7.94 | 38.18 | 12.99 | 10.31 |
| 02-B | 106.66 | 32.76 | 8.60 | 50.29 | 15.01 | 9.85 |
| 03-B | 107.58 | 32.20 | 8.45 | 49.09 | 17.84 | 10.13 |
| 04-A | 85.87 | 29.67 | 8.03 | 35.94 | 12.23 | 9.97 |
| 05-A | 104.52 | 32.81 | 8.39 | 47.12 | 16.20 | 10.11 |
| 06-B | 102.61 | 33.15 | 8.30 | 48.00 | 13.16 | 10.27 |

Compared with the mean of 01-A and 04-A, 05-A has **18.205 additional sampled
CPU-seconds**: 4.150 before the first reload, 0.405 in the four reload brackets,
10.060 in the three gaps, and 3.590 after the final reload. Thus **17.800 CPU-seconds**
of the difference is outside reload brackets. That difference is distributed
across the run; an isolated initial-convergence cost cannot account for it.

The first ten sampled seconds differ by only -0.030 CPU-seconds for 05-A versus
the mean of the other A legs. This slice starts at the first sampler row and ends
at the first row at least ten wall seconds later. Its actual monotonic duration
is 10.000049–10.000365 seconds across the six legs. It is not an exact convergence
boundary: the harness reports convergence relative to its own start, without a
wall timestamp for that event. Before-reload-1 combines startup, convergence,
churn warmup and control; the subsequent gaps include ongoing churn. They are
not idle controls.

Summed voluntary task-switch deltas over the sampled trace are 2,451,051,
2,663,788 and 3,551,737 for 01-A, 04-A and 05-A respectively. More switches
accompany the high-CPU baseline launch, but neither counter identifies the work
or establishes whether scheduling causes the CPU difference.

## Resolution and limits

The traces have 5,123–5,125 samples per leg over 128.050–128.100 sampled seconds.
Median intervals are approximately 25 ms; individual monotonic intervals range
from 18.918 to 31.086 ms. Every recorded thread-read race count is zero. Samples
read several proc/cgroup files sequentially, so fields are not atomic; process
CPU counters are quantized. These limits apply to endpoint attribution as well
as the original reload brackets.

The measurements establish substantial within-binary variation outside reload
windows. They do **not** distinguish environmental placement, allocator activity,
runtime scheduling, or other daemon work. Quiet admission and matching executable
bytes do not settle those alternatives. The trace also does not establish a
single persistent CPU mode per launch.

Consequently, no environmental mode classifier or daemon fix follows from this
evidence. Selecting 05-A as the only comparable baseline could give a smaller
descriptive arm difference, but one such baseline launch cannot establish a
corrected causal “about 2%” arm effect. All six legs remain in the evidence;
neither a general CPU regression nor a CPU improvement is isolated here.

## Reproduce the partition

[phases.csv](artifacts/reload-cpu-phases-2026-10/phases.csv) contains all 54 partition
intervals and six overlapping ten-second slices. It preserves endpoint values,
raw CSV line numbers, wall/monotonic timestamps, read durations and counter
deltas. Subtract each start counter from its end counter; sum the nine partition
rows per leg. Exclude `first_10s_probe` from that sum.

With the retained raw archive extracted locally, the small
[reader](artifacts/reload-cpu-phases-2026-10/analyze.py) regenerates the CSV from
`LEG/cgroup-fast.csv` and the existing public reload brackets. It checks ordered
counters and exact bracket membership without consulting the current source
revision or enforcing an evidence seal. From the repository root:

```bash
python3 docs/perf/artifacts/reload-cpu-phases-2026-10/test_analyze.py
python3 docs/perf/artifacts/reload-cpu-phases-2026-10/analyze.py "$RAW_ROOT" > /tmp/reload-cpu-phases.csv
diff -u docs/perf/artifacts/reload-cpu-phases-2026-10/phases.csv /tmp/reload-cpu-phases.csv
```

The reader's regression rejects a reload boundary shifted off its actual sample.
Regeneration requires the unpublished raw traces; the endpoint subset does not
recover per-thread or environmental data that were never recorded.
