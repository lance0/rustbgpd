# Readiness-checkpoint clock: S2 reload A/B — 2026-10-03

Skipping the clock read at idle readiness checkpoints (#2920) cut the
daemon's median SIGHUP-to-reload-complete time from 1,137.15 ms to 959.15 ms
on the 700-peer, 400,400-prefix S2 policy reload, with separate per-reload
ranges.

The run was measured on 2026-10-03 and is published retroactively on
2026-10-10 from the retained raw data. It is the measurement behind the
v0.74.0 changelog entry for #2920, which reads: "the median
SIGHUP-to-reload-complete time fell from 1,137 ms to 959 ms (4 legs and 16
reloads per arm)". The receipt's medians round to those figures.

## Question and arms

#2920 lets `replacement_readiness_checkpoint` return before reading the clock
when neither the readiness lane nor the operator-summary lane holds a query.
Policy-transition staging calls the checkpoint per element, so a reload with
no queued queries no longer reads the clock on every call. The question was
how much that changes the S2 reload clocks.

| Arm (campaign label) | Source commit | Tree |
|---|---|---|
| `main`: main before #2920 | `aae915bb49600a6711f2edecc6d374038ebe061a` | `c10d9494ee2a923d856664c31613b042b3f65dca` |
| `fast`: #2920 head as measured | `5fedc3499cadf3e99c7996c8b8190a08fc3fd47e` | `e47fff14f512c2852c691783dc367855dff6a2f2` |

`5fedc3499` is a direct child of `aae915bb4`, so the arms differ only by
the #2920 change at that point. #2920 merged as `ff666f7ec`. Its two later
commits added a changelog fragment and changed only code compiled under
`cfg(test)` or the non-default `bench-internals` feature, plus a unit test.
The merged build was not measured.

## Shape and method

- **Shape:** IXP matrix S2: 700 peers, all 700 changed on each reload,
  400,400 prefixes, four policy reloads per leg after a 30-second control
  window.
- **Driver:** `just bench-headline`
  ([`run-campaign.sh`](../../bench/scale/headline/run-campaign.sh)) with
  `CELLS=matrix MATRIX_SCENARIOS=s2 RUNS=4`. Each arm was built with
  `cargo build --release --locked -p rustbgpd -p rustbgpctl -p rs-config-render`
  and its own `reloadstall` with the `scale` profile.
- **Order and count:** ABBAABBA (`main`, `fast`, `fast`, `main`, `main`,
  `fast`, `fast`, `main`). Four process legs per arm and four reloads per leg:
  n = 16 reloads per arm. The reloads in one leg share a daemon process, so
  they are correlated observations; per-leg medians (n = 4) are given as
  well.
- **Guards:** every leg passed its runner with two accepted host-quiet
  samples (all 64 governors `performance`), a 300 s cool-down (recorded in
  the runner logs, kept outside the repository), the daemon in
  a cgroup scope with `memory.swap.max=0`, and the kernel swap counters
  unchanged across the window. All 32 reloads committed with 700 members.
  No leg or reload was excluded or retried.
- **Window:** 2026-10-03 08:47–09:49 local time. An earlier invocation at
  08:33 started no leg, because the shared host lock was busy; see the
  [artifact notes](artifacts/readiness-checkpoint-clock-2026-10/README.md#notes).
- **No predeclared bars.** This was a PR measurement without an acceptance
  contract. The tables below say whether the arms' ranges are separate; that
  is a description, not a pass/fail rule.

## Results

Reload clocks, in ms unless marked. "Per reload" is the range and median over
16 reloads per arm; "leg medians" is the range of the four per-leg medians.

| Metric | `main` per reload (median) | `fast` per reload (median) | Median change | `main` leg medians | `fast` leg medians |
|---|---|---|---:|---|---|
| Daemon: SIGHUP → config reload complete | 1,056.6–1,175.0 (1,137.15) | 916.8–1,007.6 (959.15) | −178.00 (−15.7%) | 1,074.0–1,157.9 | 936.8–964.4 |
| Harness: completion p50 (s) | 1.09–1.22 (1.16) | 0.93–1.02 (0.99) | −0.17 s | 1.095–1.180 | 0.965–0.990 |
| Harness: changed-observer max gap p50 | 467.4–539.5 (480.0) | 376.4–443.9 (391.6) | −88.44 | 470.1–507.7 | 387.0–400.8 |
| Daemon: RIB transition, peer-manager span | 487.5–521.3 (495.5) | 355.5–387.3 (366.95) | −128.55 (−25.9%) | 495.1–500.3 | 363.7–367.9 |
| Daemon: RIB transition, RIB-manager record | 487–512 (494.5) | 355–381 (365.0) | −129.5 (−26.2%) | 494.0–497.5 | 362.5–366.0 |
| Daemon: generation total | 1,014.2–1,138.0 (1,094.8) | 876.6–965.7 (917.3) | −177.5 | 1,033.4–1,114.9 | 896.5–922.6 |
| Daemon: cohort prestage round trip | 434–523 (494.0) | 367–456 (411.5) | −82.5 | 445.0–514.0 | 384.5–418.0 |
| Daemon: deferred refresh dispatch | 71.8–95.7 (82.5) | 112.5–148.6 (130.7) | +48.25 | 80.1–89.3 | 122.2–134.4 |

- **Reload completion.** The daemon's SIGHUP-to-complete interval, the
  harness's completion p50 and the changed-observer stall p50 are all lower
  on `fast`, with separate per-reload ranges.
- **Where the time went.** The RIB transition fell by about 129 ms at the
  median, and the generation total by about 178 ms. The cohort prestage
  round trip also fell, with overlapping per-reload ranges but separate
  per-leg medians. Deferred refresh dispatch rose by about 48 ms, with
  separate ranges; the net change is still a reduction.
- **The two RIB metrics.** Both come from the daemon log and are reported
  under separate names because they measure different spans:
  - the **peer-manager span** is `cohort_rib_transition_us` in the "reload
    generation phase timing" record, from sending the cohort transition to the
    RIB manager until its reply. This is `daemon_rib_transition` in
    `summary.csv`.
  - the **RIB-manager record** is `elapsed_ms` in the "RIB export-policy
    transition completed" record, from the RIB manager creating the
    transition to its commit, truncated to whole milliseconds. This is the
    487–512 ms versus 355–381 ms figure used in later attribution work.

Memory, per leg (n = 4 per arm), MiB:

| Metric | `main` (median) | `fast` (median) | Median change |
|---|---|---|---:|
| Daemon cgroup `memory.peak` | 995–1,173 (1,039) | 1,018–1,282 (1,106) | +68 |
| Daemon VmHWM | 556–565 (563) | 556–565 (562) | −1 |
| Peak 5 s process-tree RSS sample | 471–480 (474) | 491–505 (502) | +28 |
| Settled RSS (last 5 s sample) | 364–367 (364) | 363–368 (365) | +1 |

The cgroup peak and VmHWM ranges overlap. The 5 s RSS sample is higher on
every `fast` leg, but a 5 s sample misses shorter transients and depends on
sampling phase, while the daemon's VmHWM, its actual resident peak, shows no
difference. This run does not establish a memory change in either direction.

Session establishment was unaffected: the first-to-700th
`session established` span was 0.731–0.752 s on `main` and 0.738–0.752 s
on `fast`.

## Relation to the public wording

- **Changelog (v0.74.0):** "1,137 ms to 959 ms" is the per-reload median of
  the daemon's SIGHUP-to-complete interval, 1,137.15 ms and 959.15 ms here,
  rounded. It refers to `5fedc3499` against `aae915bb4`, not to a
  measurement of the merged commit.
- **#2920 description:** its generation total (1,094.8 → 917.3 ms),
  SIGHUP-to-complete, prestage round trip (494 → 411.5 ms, per-leg medians
  445–514 vs 384.5–418) and deferred dispatch (82.5 → 130.7 ms) figures match
  this bundle. Its "RIB transition 495.5 → 367.0 ms" is the peer-manager span;
  the second median is 366.95 ms, rounded.

## Does not establish

- **Another shape or workload.** Only the S2 policy reload was measured: no
  S1/S3 reload, IRR, route-server scale or cross-daemon result.
- **Operator-read latency.** The run issued no timed readiness or
  operator-summary queries, so the change's effect on a query that arrives
  during a transition was not measured here.
- **The merged build.** `ff666f7ec` and later releases were not measured in
  this run.
- **Statistical significance.** Four legs per arm; the 16 reloads per arm
  are correlated within each leg.
- **A memory improvement or regression,** as above.

## Provenance

- **Host class:** AMD Ryzen Threadripper 7970X, 64 CPUs, all `performance`
  governors, affinity 0–63 inherited by every runner, harness and daemon;
  Linux 7.0.0-30-generic; cgroup v2. Rust 1.99.0.
- **Binaries:** `main` daemon SHA-256
  `d99bdc7d0fec9ecfa2dacebb6b2ec7f5d3ed354a69490ed01095615a4ee9c874`, `fast`
  daemon SHA-256
  `d2b1ac4c6ad49857fd2a642685fb2d687a7f02776e80a62dcc7f89837a895147`. Each
  arm's runner provenance names a local, never-published commit with that
  arm's tree.
- **Evidence:** the [artifact bundle](artifacts/readiness-checkpoint-clock-2026-10/README.md).
  `python3 docs/perf/artifacts/readiness-checkpoint-clock-2026-10/recompute.py`
  recomputes every number above from the committed files.
