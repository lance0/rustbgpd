# TCP unsent-threshold 128 KiB screen — October 2026

A second six-leg native-loopback screen saved daemon cgroup memory with a
131,072-byte TCP unsent threshold but missed the original completion gate.

The 128 KiB candidate is **NO-GO under the unchanged +2% completion gate**:
the median of per-reload completion p50s increased **4.378%**, while the median
observed kernel cgroup peak fell **338.922 MiB**. The median of the three
independent process-leg completion medians also increased **4.762%**.

The [earlier 64 KiB screen](tcp-unsent-threshold-screen-2026-10.md) remains a
separate historical result. Both candidates reduced observed memory peaks and
both missed the completion gate against their own unset baselines. The final
recommendation is to **retain the existing socket behavior and size containers
from representative whole-cgroup reload peaks plus headroom**. No production
setting or default change follows from these experiments. The maintained
[sizing guidance](../benchmarks.md#current-evaluator-evidence) explains the
cgroup-versus-RSS distinction.

## Shape and provenance

Measured on 2026-10-06 with 700 peers, 400,400 total prefixes, and four reloads per
leg. Each source supplied 572 prefixes; all 700 observers completed the initial
exact bitmap of 399,828 received prefixes. Every reload changed all 700 peers,
retained 700 sessions, and reported zero parse errors. There were no stable
peers, paced readers, added RTT, or writer-poll diagnostics.

The predeclared order was unset/131,072, then 131,072/unset, then unset/131,072.
All six legs and 24 reloads are included. Each arm has **three independent
process legs and 12 correlated per-reload p50s**. The gate uses the pooled
median of those p50s; the separate process-leg summary exposes the independent
sample count. Neither summary establishes statistical significance.

The daemon and harness are the exact binary bytes used for the 64 KiB screen,
from Rust source base `dcc9b6384d2f7931d4aa905b0cdc1e55efd790c4`. The wrapper and
sampler are separately pinned to `7d787ac4bd7311b89a14243cd331e535d882eca5`.
Before/after source, binary, tool, and environment attestations matched across
all six new legs. [Provenance](artifacts/tcp-unsent-threshold-128k-screen-2026-10/provenance.json)
records the full hashes, build commands, workload inputs, Rust 1.99.0, and Linux
7.0.0-30-generic x86_64. The two screens' baselines are not pooled.

Every leg held the shared host mutex and passed two quiet samples at least
30 seconds apart, with load below 2, all 64 CPU governors in performance mode,
no detected competitors, and unchanged swap counters. Actual wrapper, runner,
sampler, socket-check, and daemon exit receipts were zero; each full 300-second
cooldown completed. Every leg had 700 unique live socket readbacks, each before
its session was established: zero for unset, 131,072 for the candidate. The host
sysctl stayed at 4,294,967,295. Original owned processes and scopes were confirmed
removed and the mutex released. Cleanup success is observed from those checks;
no separate cleanup exit file was recorded.

## Results

| Metric | Unset | 131,072 bytes | Change |
|---|---:|---:|---:|
| Median of per-reload completion p50s | 0.915911 s | 0.956007 s | +4.378%; fails +2% gate |
| Median of independent process-leg completion medians | 0.913568 s | 0.957069 s | +4.762% |
| Median of changed-peer maximum-gap p50s | 222.090 ms | 220.979 ms | −0.500% |
| Median observed kernel daemon-cgroup peak | 1,106.563 MiB | 767.641 MiB | −338.922 MiB; meets ≥100 MiB component |
| Median burst CPU, outer sample bracket | 2.195 CPU-s | 2.425 CPU-s | +10.478% |
| Median requested burst duration | 0.969761 s | 1.010652 s | — |
| Median measured outer bracket width | 1.000000 s | 1.025007 s | — |
| Median preceding one-second control CPU, outer bracket | 0.545 CPU-s | 0.870 CPU-s | — |
| Worst observer completion | 1.060001 s | 1.128042 s | — |
| Worst changed-peer maximum gap | 497.914 ms | 433.010 ms | — |

| Unset leg / candidate leg | Completion p50 median change | Observed cgroup peak reduction |
|---|---:|---:|
| 1 / 2 | +6.905% | 294.305 MiB |
| 4 / 3 | +6.206% | 338.922 MiB |
| 5 / 6 | −0.623% | 294.766 MiB |

Per-reload completion p50s ranged from 0.860024–1.007529 seconds unset and
0.937196–1.048013 seconds with the candidate. Maximum-gap p50s ranged from
211.714–304.013 ms and 214.531–254.732 ms respectively. Observed kernel cgroup
peaks ranged from 1,037.668–1,113.547 MiB unset and 742.902–819.242 MiB with the
candidate. All original p95 and maximum fields, exact peak bytes, and arithmetic
are retained in the [compact evidence](artifacts/tcp-unsent-threshold-128k-screen-2026-10/README.md).

## Limits and recommendation

Full-trace CPU was 82.42, 73.76, and 106.80 CPU-seconds for unset, versus 108.71,
111.03, and 103.37 CPU-seconds for the candidate. Observed traces span about
128.1 seconds each. Baseline and preceding-control variation remains included
without a source-level explanation. Burst CPU totals cover different durations
and approximate trigger alignment; they are not normalized rates. The compact
comparison also reports CPU divided by the measured bracket width, separately
from the totals and controls. Neither measure counts asynchronous writer wakeups.

Task switches and future polls cannot discharge the unresolved writer-wakeup
gate. The frozen build lacks task-ID tracing and task/socket attribution.
Near-largest-current `memory.stat` anon/sock splits are non-atomic observations,
not attribution of the exact kernel peak. Kernel peaks were observed before
shutdown and do not guarantee final lifetime maxima or a safe production limit.

Both measured candidates failed native completion acceptance, so this bounded
investigation ends with documentation and sizing guidance. It does not proceed
to another threshold or claim slow-reader, stopped-reader, or 20 ms RTT fleet
qualification. Separate functional container smokes establish driver behavior
only. Use the unchanged socket behavior and measure representative reloads when
setting container memory limits; include kernel TCP memory and workload-specific
headroom above the observed whole-cgroup peak.
