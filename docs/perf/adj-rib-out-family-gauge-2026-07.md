# Adj-RIB-Out family-gauge fanout receipt (July 2026)

## Decision

Ship the family-selective gauge refresh. Against the immediately preceding
unchanged-behavior harness commit, the target improves the 256-peer cell by
11.69% and the 1,000-peer cell by 14.98%. Both 95% confidence intervals exclude
zero, and all retained preflight-valid paired attempts favor the target.

This is a route-server-shaped steady-state fanout measurement, not a claim
about all daemon work. The fixture holds one homogeneous update group with 64
changed IPv4-unicast routes and 8, 64, 256, or 1,000 peers. Each persistent
fleet is prewarmed; setup then alternates MED 50/51 so every timed pass carries
a real wire-visible change.

## Control and target

- Control: `e94760217119f3b6a6521bf8c4002e9da4266b25`, the immediately
  preceding harness commit. It refreshes all seven Adj-RIB-Out family gauges
  after every route-bearing commit.
- Target: `a2fb8cb5b6a07452031e5e8fff9854c4bcc96e7f`. It derives a seven-bit
  touched-family mask from the final post-OTC, post-exact-export commit vectors
  and refreshes only those families. `PeerUp` eagerly creates all seven zero
  series so the scrape shape remains stable.

Both builds run the same receipt instrumentation. The accounting cost is one
mask `count_ones` and one total-counter addition in both revisions; the target
does not receive a cheaper benchmark-only counter path.

The measured interval contains manager distribution, one real
`SessionExportEncoder` exact-export probe per changed route, compatible reuse
across the one update group, authoritative Adj-RIB-Out commit, metric refresh,
and bounded-channel enqueue. Route construction, Loc-RIB replacement and
recompute, receipt checks, and receiver drains are outside the interval. The
measurement does not include the session writer, socket, or network I/O.

## Primary pinned A/B

Criterion used its normal 3-second warmup, 5-second measurement, and 10 samples.
The control and target had separate Cargo target directories, and execution was
pinned to logical CPU 5 with the `performance` governor.

| Peers | Control mean | Target mean | Mean change | 95% CI for change |
|------:|-------------:|------------:|------------:|------------------:|
| 8 | 61.724 us | 55.843 us | -9.53% | -10.22% to -8.99% |
| 64 | 315.796 us | 273.362 us | -13.44% | -13.94% to -12.90% |
| 256 | 1.194 ms | 1.055 ms | -11.69% | -12.34% to -11.07% |
| 1,000 | 4.830 ms | 4.106 ms | -14.98% | -16.05% to -13.93% |

Two shorter retained pairs at the release-gating 256/1,000-peer sizes also
favored the target:

| Pair | 256 peers | 1,000 peers |
|-----:|----------:|------------:|
| 2, target then control | -14.23% | -11.11% |
| 3, control then target | -14.53% | -22.41% |

The spread between short pairs is why the full Criterion confidence interval,
not a single short point estimate, is the shipping control. Exact unrounded
estimates and environment metadata are retained under
[`artifacts/adj-rib-out-family-gauge-2026-07/`](artifacts/adj-rib-out-family-gauge-2026-07/).

## Regression controls

The existing 256-peer fanout sentinels stayed below the 3% regression ceiling.
These older fixtures are equality-suppressed second calls and therefore are
regression controls only, not evidence for the optimization:

| Control | Target change | 95% CI |
|---------|--------------:|-------:|
| RR, no policy | +1.68% | +1.51% to +1.81% |
| RR, representative policy | +1.72% | +1.33% to +2.22% |
| Route server, homogeneous remote ASN | +0.84% | +0.51% to +1.16% |
| Route server, distinct remote ASNs | +0.99% | +0.71% to +1.27% |

The first, third, and fourth cells use a 1-second warmup and 2-second
measurement. The policy cell was rerun in reverse target/control order with
the full 3-second warmup and 5-second measurement after a shorter first pair
crossed the ceiling; the retained reverse pair bounds the target regression
below 3%. Mixed-family correctness is not inferred from a unicast timing
fixture: the production test commits VPN-only and unicast-plus-VPN payloads,
checks exact sentinel values for every family, and fails under unconditional
refresh.

## Path receipts and load-bearing proofs

Every timed iteration asserts all of the following before the sample can be
accepted:

- exactly one update group containing every peer, with no ungrouped or dirty
  fallback;
- one full real exact-export probe batch over all 64 changed routes and
  `64 * (peers - 1)` compatible reuse hits;
- one successful route-bearing commit and enqueue per peer;
- exactly one unicast gauge write per peer in the target (`0x01` mask), versus
  seven per peer in the control (`0x7f` mask); and
- exact first-peer gauge values `[64, 0, 0, 0, 0, 0, 0]`, plus exactly one
  route-bearing envelope per receiver.

These checks are load-bearing. Suppressing the MED toggle was injected and the
benchmark failed before measurement because zero of 64 replacements changed
the Loc-RIB best. Bypassing the real encoder makes the probe counts red;
breaking grouping makes group membership or reuse red; a dropped send makes
enqueue/channel checks red; and corrupting the grouped family value makes the
exact gauge vector red. Production tests separately seed distinct sentinels and
prove VPN-only and mixed unicast/VPN commits update only the touched series.
Restoring unconditional seven-family writes was injected and made that test
red. Removing one eager `PeerUp` series was injected and made the
series-presence test red.

## Reproduction

Build each revision in a separate target directory; sharing one directory can
silently reuse the wrong benchmark executable after switching worktrees.

```bash
taskset -c 5 env CARGO_TARGET_DIR=<control-target> \
  cargo bench -p rustbgpd-transport --features bench-internals --bench fanout \
  -- adj_rib_out_family_gauge --save-baseline lan518-control

taskset -c 5 env CARGO_TARGET_DIR=<target-target> \
  cargo bench -p rustbgpd-transport --features bench-internals --bench fanout \
  -- adj_rib_out_family_gauge --baseline lan518-control
```

Reject a run if another process becomes CPU-active on the pinned core. Two
attempts were rejected before retention after a local inference server became
active; they are not mixed into the table or artifact estimates.
