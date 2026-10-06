# TCP unsent-threshold screen — October 2026

A six-leg native-loopback screen found lower daemon cgroup memory peaks with a
65,536-byte TCP unsent threshold, but missed the predeclared completion gate.

The frozen 64 KiB candidate is **NO-GO under the original +2% completion gate**:
the median of per-reload completion p50s increased **3.846%**, while the median
observed kernel cgroup peak fell **275.559 MiB**. This decision applies to this
candidate and screen. The investigation remains open; a 128 KiB candidate is
queued and unmeasured. This receipt introduces no production setting or default.

## Shape and provenance

Measured on 2026-10-06 with 700 peers and 400,400 total prefixes (572 per source).
All 700 observers completed the initial exact bitmap of 399,828 received prefixes.
Each leg performed four reloads changing all 700 peers, with no stable peers;
every reload retained 700 sessions and reported zero parse errors. Native
loopback used zero added RTT, unpaced readers, and writer-poll diagnostics off.
The harness cell's `pass` records successful execution, separately from the
candidate's failed acceptance gate.

The arm order was unset/65,536, then 65,536/unset, then unset/65,536: three
independent legs per arm, with **12 correlated per-reload p50s per arm**. No leg
or reload was excluded. The completion gate compared the pooled median of those
p50s; these data do not establish statistical significance.

The Rust source base was `dcc9b6384d2f7931d4aa905b0cdc1e55efd790c4`; the
experiment wrapper was `f98005e6b2a5c62fb5ae574d07b551865b6070cc`. Before/after
attestations matched source, binaries, tools, and environment across all six
legs. The build used Rust 1.99.0 on Linux 7.0.0-30-generic x86_64.
[Provenance](artifacts/tcp-unsent-threshold-screen-2026-10/provenance.json)
records full commit, tree, binary, tool, and environment hashes plus build
commands and workload inputs.

A shared host mutex serialized execution. Each leg passed two quiet samples at
least 30 seconds apart, with load below 2, all 64 CPU governors in performance
mode, no detected competitors, and unchanged swap counters. Wrapper, runner,
sampler, socket readback, and daemon exit receipts were zero. Cleanup succeeded
by observation of removed scopes and processes; no separate cleanup exit file
was recorded. Every leg retained a full 300-second cooldown. Live socket checks read zero for the unset arm and
65,536 for the candidate; the host sysctl stayed at 4,294,967,295. All owned
processes and scopes were removed and the mutex released. The first leg's
recorder was suspended for 54.2 seconds, then resumed before teardown; actual
wait and cooldown evidence remained intact.

## Results

| Metric | Unset | 65,536 bytes | Change |
|---|---:|---:|---:|
| Median of completion p50s | 0.929483 s | 0.965232 s | +3.846%; fails +2% gate |
| Median of changed-peer maximum-gap p50s | 231.909 ms | 224.868 ms | −3.036% |
| Median observed kernel daemon-cgroup peak | 1,064.395 MiB | 788.836 MiB | −275.559 MiB; meets ≥100 MiB component |
| Median burst CPU, outer sample bracket | 2.295 CPU-s | 2.435 CPU-s | +6.100% |
| Median preceding one-second control CPU, outer bracket | 0.785 CPU-s | 0.855 CPU-s | — |
| Median CPU across the observed trace | 103.940 CPU-s | 105.730 CPU-s | +1.722% |
| Worst observer completion | 1.093101 s | 1.119458 s | — |
| Worst changed-peer maximum gap | 489.035 ms | 441.416 ms | — |

Matched pairs expose timing variation hidden by the pooled result:

| Unset leg / candidate leg | Completion p50 median change | Observed cgroup peak reduction |
|---|---:|---:|
| 1 / 2 | −3.945% | 319.941 MiB |
| 4 / 3 | +8.714% | 275.559 MiB |
| 5 / 6 | +4.053% | 252.188 MiB |

Per-reload completion p50s ranged from 0.877346–1.028365 seconds unset and
0.923313–1.025800 seconds with the candidate. Maximum-gap p50s ranged from
217.236–317.745 ms and 214.413–254.483 ms respectively. Per-leg observed kernel
peaks ranged from 1,043.191–1,084.648 MiB unset and 764.707–791.004 MiB with the
candidate. All 24 original reload rows, including p95 and maximum fields, are
preserved in the [compact evidence](artifacts/tcp-unsent-threshold-screen-2026-10/README.md).

## Limits and next decision

Leg 4 consumed 69.07 CPU-seconds across its observed trace, compared with roughly
104–107 CPU-seconds for the other five legs. Auditing source, environment,
configuration, policies, and observed lifetimes did not explain the lower
background/control CPU. It remains included. Burst CPU uses outer sample
brackets around each reload; requested durations and bracket excess are retained
alongside preceding one-second controls. Median requested burst duration also
increased, from about 0.977 to 1.024 seconds, so the CPU totals are not normalized
rates. These are whole-daemon measurements, without source-level attribution.

The memory result is the kernel's observed, pre-stop whole-daemon cgroup peak,
not a guarantee about the final lifetime peak or a production memory cap.
Published `memory.stat` anon/sock splits were read near the largest sampled
`memory.current`; they cannot atomically attribute the kernel peak. Sampling
quality and read widths are preserved per leg.

Actual asynchronous writer wakeups remain unresolved. Future polls and daemon
task switches do not count writer wakeups; the frozen build lacks task-ID tracing
and task/socket attribution. Raced task-switch windows are explicitly marked in
the CPU extract. The lower stall median does not discharge that gate.

The native completion failure prevents fleet qualification for this candidate.
Slow-reader, stopped-reader, and 20 ms RTT fleet acceptance remain unmeasured;
separate 12-peer functional smokes establish driver behavior only. This is a
single-daemon screen, not a canonical cross-daemon campaign. The memory reduction
supports continuing the investigation, with 128 KiB still requiring its own
measurements and the original acceptance criteria.
