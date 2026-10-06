# Export-probe delta S2 screen — October 2026

Preserving export probes through route churn passed the predeclared timing bars
for a six-leg, 700-peer policy-reload screen on 2026-10-06.

Changed-observer stall p50 improved **80.877 ms** across the 12 correlated
reloads per arm and **79.788 ms** across the three process-leg medians. Both
exceed the required 60 ms. All nine timing endpoints stayed within the allowed
2% regression under both aggregation rules. The narrowest margin was the
three-leg median of first-generation update p95: **+1.841%**, only 0.159
percentage points below the limit. This is a pass for the measured S2 shape,
with increased CPU and voluntary task switching; it is not a general resource
improvement or a result for another workload.

## Scope and provenance

The screen used 700 peers, 400,400 prefixes, four reloads changing all 700 peers,
and a 30-second control window. Each arm ran in three separately launched
processes, ordered **ABBAAB**. The 12 reloads per arm are correlated observations,
not 12 independent repetitions. Every reload retained 700 sessions and zero
parse errors. All six native cells and their actual harness, daemon, cleanup,
wrapper, runner, sampler and identity checks passed. No leg or reload was
excluded or retried.

The baseline source was `19842a5a114287af7a8f5ae66407aaacc9d0142a`; the candidate
was `3cf0dc277dc2f729d01e40207fbdab2d2e5fda11`. Both daemons used the identical
baseline-produced `reloadstall` binary. The candidate shares route and next-hop
vectors through `Arc<Vec<_>>` and reserves one transition slice of headroom
before the fence. This avoids copying the complete vector buffers when sealing;
compaction, scans, fallback allocation and final-owner destruction retain their
existing costs.

Both release builds used default features and the same package selection:

```bash
cargo build --release --locked -p rustbgpd -p rustbgpctl -p rs-config-render
```

The candidate build compiled the RIB, transport and daemon. Cached CLI and
renderer artifacts retain their original producer identities in
[provenance.json](artifacts/export-probe-delta-arcvec-2026-10/provenance.json).
Source/tree, daemon/harness bytes, native driver sources and measurement methods
were checked before and after each leg. The toolchain was Rust 1.99.0 on Linux
7.0.0-30-generic x86_64.

The native recipe is `just bench-ixp-matrix rustbgpd`. The frozen wrapper invoked
its `bench/scale/matrix/run-matrix.sh rustbgpd` driver with
`N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=4 CONTROL_SECS=30`, empty
`CHANGED_PEERS`, `FLAPSTORM`, `FLAP_ROUNDS` and `PROBE_PREFIXES`, and
`RUST_LOG=info,rustbgpd_rib::clean_export_probe=debug` on both arms.
`COMPETITOR_GENERATION=historical` is the native receipt vocabulary used by this
rustbgpd-only campaign; no competitor daemon or fresh competitor version was
measured.

Execution ran from 19:05:56 to 19:52:53 UTC. Each leg held the shared host lock
and passed two quiet samples at least 30 seconds apart: load 1.02–1.26, all 64
governors in performance mode, no detected competitors and unchanged swap
counters. Every leg retained the native 300-second cooldown, including the
final leg. The observed scope limits were `memory.max=max` and
`memory.swap.max=0`; the native 100 GiB RSS abort guard was unchanged. All owned
processes and scopes were removed, the generated scenario was verified against
its archive before removal, and the host lock was released.

## Timing bars

For p50 and p95 endpoints, the first comparison takes the median of the 12
per-reload percentiles. For maximum endpoints, it takes the **actual worst of
all 12 reloads**. The second comparison takes each process leg's four-reload
median, then the median of the three legs per arm. Both comparisons must stay
within +2% for every endpoint; both stall-p50 gains must reach 60 ms.

| Endpoint | A, 12 reloads | B, 12 reloads | Change | A, three-leg median | B, three-leg median | Change |
|---|---:|---:|---:|---:|---:|---:|
| Completion p50 (s) | 0.769401 | 0.752154 | −2.242% | 0.762882 | 0.758231 | −0.610% |
| Completion p95 (s) | 0.809236 | 0.789740 | −2.409% | 0.799874 | 0.801341 | +0.183% |
| Completion maximum (s) | 0.890363 | 0.891329 | +0.108% | 0.806341 | 0.807953 | +0.200% |
| Changed-observer maxgap p50 (ms) | 169.5165 | 88.6395 | −47.710% | 169.5165 | 89.7290 | −47.068% |
| Changed-observer maxgap p95 (ms) | 280.7330 | 167.0055 | −40.511% | 281.5725 | 172.7750 | −38.639% |
| Changed-observer maxgap maximum (ms) | 385.8620 | 222.5500 | −42.324% | 329.6165 | 202.8330 | −38.464% |
| First-generation update p50 (ms) | 635.6850 | 616.4695 | −3.023% | 624.6815 | 619.4265 | −0.841% |
| First-generation update p95 (ms) | 754.4725 | 753.4535 | −0.135% | 740.6540 | 754.2925 | +1.841% |
| First-generation update maximum (ms) | 851.8520 | 863.4860 | +1.366% | 794.8230 | 789.3725 | −0.686% |

The six process-leg medians show variation within each arm:

| Leg | Completion p50 (s) | Changed-observer maxgap p50 (ms) | First-generation update p95 (ms) |
|---|---:|---:|---:|
| 01-A | 0.753822 | 183.2215 | 740.4275 |
| 02-B | 0.748837 | 84.3985 | 745.8985 |
| 03-B | 0.760576 | 89.7290 | 754.2925 |
| 04-A | 0.762882 | 163.2955 | 767.1980 |
| 05-A | 0.794948 | 169.5165 | 740.6540 |
| 06-B | 0.758231 | 101.3780 | 761.8350 |

All exact rows, all nine per-leg medians and both gate calculations are in the
[compact evidence](artifacts/export-probe-delta-arcvec-2026-10/README.md).
Three launches per arm and rotated ordering do not establish statistical
significance or a guarantee that another run stays within the narrowest margin.

## Path and resource observations

The candidate used 11 resize paths and one patch path. Every reload had 128
dirty keys, retained a valid proof and entered Validate with
`full_probe_count=0`. No clean-reuse or full-fallback path occurred in this
workload. Reconciliation preceded sealing with `phase=fenced`, then proof
validation, Validate entry, commit and reload-phase completion.
Reconciliation elapsed time had a 5.595 ms median and 4.893–18.155 ms range.
All 12 seal events recorded `elapsed_us=0`: that is integer-microsecond timer
resolution, not literal zero work. Validate's elapsed value is cumulative and
does not isolate full-probe cost.

| Resource observation | A median | B median | Change |
|---|---:|---:|---:|
| Reload-window CPU, outer bracket | 2.015 CPU-s | 2.105 CPU-s | +4.467% |
| Voluntary task switches in reload bracket | 11,298.5 | 18,925 | +67.500% |
| Involuntary task switches in reload bracket | 100 | 85.5 | −14.500% |
| CPU across sampled trace lifetime | 86.760 CPU-s | 106.660 CPU-s | +22.937% |
| Observed kernel cgroup peak | 1,069.227 MiB | 1,014.914 MiB | −5.080% |
| Sampled RSS peak | 563.137 MiB | 545.020 MiB | −3.217% |
| Maximum observed approximate VmHWM | 569.555 MiB | 555.977 MiB | −2.384% |

CPU and task-switch windows enclose each reload with at most 24.963 ms of
leading and 22.411 ms of trailing sample uncertainty. No thread-read race was
recorded, but whole-daemon task switches do not count writer wakeups or
attribute cost to a function. Sampled trace-lifetime CPU is a separate interval:
the baseline legs used 86.76, 85.87 and 104.52 CPU-seconds, while candidate legs
used 106.66, 107.58 and 102.61. This variation remains in the receipt.

Memory medians use one observation per process leg. Native and fast-sampler
kernel peaks matched in all six legs. Cgroup charge is separate from daemon
RSS; observed pre-stop peaks are not guaranteed final lifetime maxima.
`memory.stat` near the largest sampled `memory.current` does not atomically
attribute the kernel peak. Approximate VmHWM decreased 39, 30, 35, 41, 38 and
39 times across the six raw traces; those observations were retained.

The transition commit timer fell from a 201 to 70 ms median, but ends before
terminal input retirement and scheduling resume. Neither that timer nor the
wider caller-await timer measures exact actor-fence release, and neither was
used to substitute for observed stall. The narrow diagnostic filter was active
in both arms; an uninstrumented production-overhead comparison was not run.

## Earlier candidates and limits

Earlier campaigns remain failed historical evidence. The initial candidate
`c2bccd375914494f6d01a6f7ca223d6643ae207f` met the stall-gain component but
regressed median completion by 6.972%. The vector candidate
`c5db6464fae6180272e1befb291cb3eb33d8a57a` improved stall p50 by only 43.2195 ms
and regressed actual worst completion by 2.593%, so it also missed the unchanged
bars. Their distinct source identities, results and raw-analysis hashes remain
in compact provenance. This fresh campaign does not turn those results into
passes or establish a cross-campaign causal comparison.

The current pass is limited to the measured all-peer S2 policy-reload shape.
Other scales, address-family mixes, reader pacing, network delay, S3 behavior
and cross-daemon comparisons were not qualified by this campaign. The resource
increases above remain part of the measured timing tradeoff.
