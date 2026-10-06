# IRR reload at 0% overlap: current source, BIRD 3.3.3 and OpenBGPD 9.3 — 2026-10-06

Three sequential roots measured unreleased rustbgpd source `dcc9b6384`
against BIRD 3.3.3 and OpenBGPD 9.3 on one host, from 06:47:38 to
08:17:33 UTC on 2026-10-06. Each root ran all three daemons at 320 members
× 183,040 generated IPv4 prefixes, 0% received-view overlap and four
reloads per daemon. All 36 reload rows passed with 320/320 sessions and
zero parse errors. No root is excluded.

rustbgpd's completion p50 was 0.578–0.606 s, against BIRD's 12.493–14.490 s
and OpenBGPD's 44.429–59.541 s. Its all-observer gap p50 range overlapped
OpenBGPD's. These are observations of this workload and configuration,
with three independent daemon launches per implementation. They do not
attribute a change to the comparator pins or establish a release result.

## Results

Each reload produces a percentile across observers. The ranges below are
the minimum and maximum of those 12 per-reload percentiles per daemon;
parentheses give their pooled median. The four reloads within a root share
one daemon process and are correlated, so there are three independent
process runs per daemon, not twelve. No confidence interval or statistical
significance is claimed.

| Metric | rustbgpd `dcc9b6384` | BIRD 3.3.3 | OpenBGPD 9.3 |
|---|---:|---:|---:|
| Completion p50, s | 0.578–0.606 (0.590) | 12.493–14.490 (13.408) | 44.429–59.541 (48.985) |
| Completion p95, s | 0.586–0.640 (0.620) | 14.410–15.510 (15.003) | 44.432–59.544 (48.997) |
| All-observer gap p50, ms | 376.296–403.276 (389.680) | 822.648–1,437.831 (878.406) | 371.250–443.728 (414.560) |
| Changed-observer gap p50, ms | 376.296–403.276 (389.680) | 816.845–887.045 (863.952) | 371.250–443.728 (414.560) |

**Completion** measures delivery of the expected policy generation to each
observer. **All-observer gap** measures each observer through the slowest
changed observer's completion and includes the trailing gap to that
boundary. **Changed-observer gap** stops at that observer's own completion
and excludes a trailing gap. Both include the leading gap from the reload
trigger to the first UPDATE. All 320 observers are changed in these cells,
but the different boundaries can still produce different gap values.
The raw rows retain p50, p95 and maximum for both gap fields, as well as
completion p50, p95 and maximum.

The completion p50 medians within each root were:

| Root | rustbgpd, s | BIRD, s | OpenBGPD, s |
|---|---:|---:|---:|
| 1 | 0.590506 | 13.077457 | 49.254819 |
| 2 | 0.586947 | 13.292816 | 48.851964 |
| 3 | 0.589101 | 13.524961 | 49.024663 |

These per-root medians are distinct from the pooled medians in the first
table. rustbgpd completed sooner in every reload in this campaign. Its gap
range overlaps OpenBGPD's, so that metric has no separated-range result
between the two.

## Memory

Values below are roots 1 / 2 / 3, in KiB. The artifact labels say `kB`, but
the runner divides the cgroup's byte readings by 1,024.

| Reading | rustbgpd | BIRD | OpenBGPD |
|---|---:|---:|---:|
| Cgroup peak through harness completion | 757,344 / 803,708 / 756,356 | 1,569,428 / 1,520,240 / 1,545,576 | 1,532,972 / 1,512,808 / 1,513,592 |
| Peak 5 s process-tree RSS sample | 635,484 / 650,884 / 650,380 | 1,416,236 / 1,421,072 / 1,419,512 | 1,471,008 / 1,382,684 / 1,357,396 |
| Process VmHWM at cell end | 759,304 / 803,120 / 760,324 | not recorded | not recorded |

The cgroup peak is `memory.peak` of rustbgpd's fresh, swap-fenced daemon
scope or the competitor's fresh container. It covers startup, convergence,
control traffic and the four reloads through successful harness completion,
before lifecycle probes or teardown. The exact marker is
`through_harness_completion_before_lifecycle`. This campaign used the
SIGHUP cell, so it ran no transaction lifecycle probes.

Every cgroup reading has an actual `memory.swap.peak` of zero. The native
scope also records `memory.swap.max=0`. Cgroup accounting includes anonymous
memory, page cache and kernel charges; the competitor containers also
include their `docker exec` reload clients. These are measured cell peaks,
not reload-only peaks, allocator totals or a measurement of later daemon
lifetime. Native `cg_current` is a separate point-in-time capture retained
in each readout.

VmHWM is the daemon process's resident high-water mark, read just before
termination. Sampled RSS is the largest 5 s process-tree sample and can
miss short transients. Keep these sources separate from cgroup peak. The
table describes these configurations; it does not establish a memory
ranking for other workloads or container defaults.

## Method and identities

| Item | Value |
|---|---|
| rustbgpd | Clean commit `dcc9b6384d2f7931d4aa905b0cdc1e55efd790c4`, tree `adeb355e88708a3d7ef1c96a6cd173c3f366e9f4`; release build with default jemalloc. The binary reports 0.75.0, but this is unreleased source after that tag |
| Daemon SHA-256 | `4c98759f7623858f23543754d02bca43266e5da691c62a78d3dfbc2995ab9c2d` |
| `reloadstall` SHA-256 | `49b64a73b9af6b77a6f59fd8408eccb1cbe1ec878c7fd572b3e06dea09deccc1`, same source, `scale` profile with jemalloc |
| BIRD | 3.3.3, 8 threads; `bird:v3.3.3-m101`, immutable image `sha256:fa47b7dc82a7da50ac591d17d22054aa01e3bb31c875e9346b324e907454b930` |
| OpenBGPD | 9.3; `openbgpd/openbgpd@sha256:8f4b44f25796beaecb72ab7f099a3914961ac444a9de094ffca6a4614e741412` |
| Dataset SHA-256 | `fad37b701fcd3f7f51884906f66052325f3f1e57a02528a039535ed08907c56b` |
| Toolchain and host | rustc 1.99.0; AMD Ryzen Threadripper 7970X, Linux 7.0.0-30-generic |

The [compact identity record](artifacts/irr-reload-current-comparators-2026-10-06/identity.json)
also records the CLI and renderer digests, tool versions and every workload
input. The selected comparator generation was `current`, with no smoke or
preflight override. Canonical inputs were seed 61, IRR lists of
1,000–40,000 entries, 10% change, 30 s control and four reloads at 0%
overlap. The native pre-reload topology proof recorded zero overlapping
member/prefix pairs.

Each invocation was
`bench/scale/irrreload/run-irr-reload.sh rustbgpd-sighup bird openbgpd` with
`COMPETITOR_GENERATION=current OVERLAP_FRACTION=0`. Roots ran strictly in
sequence. Within each root the order was rustbgpd, BIRD, OpenBGPD, with
300 s cooldowns and the existing host mutex and quiet gate: one-minute
load below 2.0 in two accepted samples before each cell. Daemon order was
fixed, not counterbalanced.

### Verification and extraction

The IRR verifier's `validate_root(root, "comparison")` passed for each
completed root. The queue's cross-root wrapper additionally bound the
exact commit and tree, clean source, current image pair, 0% overlap, 12
rows per root, equal environment/binary/input/dataset identities, strictly
ordered non-overlapping roots and distinct daemon process identities.
All three runners and the queue exited zero.

Per-root verification covers canonical workload inputs, process and quiet
evidence, the pre-reload topology, raw row consistency, dataset-refresh
re-extraction and exact schema 3 memory windows with zero actual swap.
The `campaigns` command was not used: it requires grouped controls, which
these comparison roots did not run.

[`summarize.py`](../../bench/scale/headline/summarize.py) extracted the native
reload and daemon-clock metrics and all three cgroup memory series.
The unchanged
[`extract-tails.py`](artifacts/cross-daemon-v0740-2026-10/extract-tails.py)
extracted all three daemons' completion and changed-gap values into
`irr-cells.csv`. The all-observer gap table above uses the separately
named `all_observer_maxgap_*` fields in the verified root `rows.csv`.
It must not be read from `changed_maxgap_*`.

## Scope and retained history

- One generated IPv4 shape at 0% overlap on one host, with three process
  runs and fixed daemon order. No grouped control, IPv6, other overlap,
  larger-fleet or live Internet-table result is established.
- This is an IRR comparison, not a refresh of IXP S1/S2/S3 or RR1000.
  GoBGP has no arm in this runner, so there is no new GoBGP performance
  measurement.
- The rustbgpd source and BIRD version both differ from the earlier
  campaign. These runs cannot isolate the effect of a pin or any runtime
  change, and they do not compare BIRD 3.3.2 directly with 3.3.3.
- The [v0.75.0 receipt](cross-daemon-v0750-2026-10.md) preserves its
  2026-10-04 to 2026-10-05 matrix and 0%/10%/50% IRR measurements against
  BIRD 3.3.2. Its numbers remain dated history.

The [compact bundle](artifacts/irr-reload-current-comparators-2026-10-06/README.md)
retains every reload row, memory readout and measurement-window marker,
with derived tables and checksums. Full daemon logs, configurations and
topology scrapes remain outside the repository; the compact bundle alone
cannot rerun full root validation.
