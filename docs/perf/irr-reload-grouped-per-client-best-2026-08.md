# Grouped per-client best-path IRR reload receipt — ADR-0126 acceptance — 2026-08

What does the RFC 7947 path-hiding mitigation cost once it is computed
per group instead of per member? The sealed
[realistic-mix receipt](irr-reload-realistic-mix-2026-08.md) priced
ungrouped per-client best-path at the canonical
320-member × 183,040-prefix shape: steady-state reload completion p50
~87 s (F = 0.1) to ~135–143 s (F = 0.5) and ~10.5–11.3 GiB sampler RSS
peak, against ~4.5 s and ~2.0–2.1 GiB for the mitigation-less grouped
control. Since that receipt sealed, ADR-0126's implementation landed:
per-client-best peers with shareable export chains now join update
groups, the winner walk runs once per group, and the runner-up lives in
a per-prefix sidecar lane. This campaign reruns the same
per-client-best cells — same shape, dataset, seed, protocol, and
instrument — with the fleets now grouped. That comparison is the
[ADR-0126](../adr/0126-shared-group-per-client-best.md) Phase 4
acceptance receipt. Eight fresh sealed artifact roots, four per overlap
point in counterbalanced A/B/B/A order, all green at one clean commit,
cross-checked by the campaign's independent verifier; the campaign's
four halted roots and its superseded green roots — three real daemon
defects, each fixed inside the campaign window — are preserved and
disclosed below.

## What the mitigation still delivers: byte-identical received views

The equivalence headline is counted on the wire, observer-side. After
the final measured reload, each of the 320 live observer stubs dumps
its final-generation received view, and the grouped campaign's views
are compared bit-for-bit against the sealed ungrouped baseline's
captures:

| Overlap F | Grouped received view (both A/B repeats) | Sealed ungrouped baseline | Verdict |
|---|---|---|---|
| 0.1 | `475e3ce4fec029d99c01ad0cdf09d0da89fef85f9f8f50fd03aa140216c6cf93` | same digest | **byte-identical** |
| 0.5 | `cf90d16f1992cec7ea99137374b859e82d7b499847a4d941994466cee5de7898` | same digest | **byte-identical** |

Every comparison root's `received-view.tsv` is bit-for-bit identical
(`cmp`, then SHA-256 above) to the corresponding capture in the sealed
realistic-mix roots — the grouped walk reproduces the ungrouped
per-client-best path's per-member views exactly, at both overlap
points, in both repeats. The standalone received-view-delta verifier
passes for both A/B repeats at both overlap points with the exact
allocation counts — 18,304 (F = 0.1) and 91,520 (F = 0.5) suppressed
runner-up pairs, matching the scenario manifest precisely — and the
four-root campaign verifier re-derives the same verdict. The
runner-up-lane gauge (`bgp_update_group_runner_up_entries`) reads
exactly 18,304 / 91,520 in the sealed comparison-cell scrapes and 0 in
the grouped control, confirming the lane holds one entry per
overlapped prefix and nothing else.

## What it costs now: cross-daemon comparison

Wire-observed, receiver-side, percentiles across all 320 observers.
r2–4 columns are the mean of reloads 2–4 (the steady-state
generations); reload 1 is listed separately. Stall =
`all_observer_maxgap_p50_ms`. RSS = per-cell peak of the 5 s
process-tree sampler, the only cross-daemon RSS instrument (it can
double-count shared mappings; close differences are not exact
allocator comparisons). The grouped-control rows are the standalone
path-hiding diagnostic — never a competitor configuration — and are
included to price the seam, per the harness protocol. Since the
ADR-0126 classifier flip, both rustbgpd cells form exactly one
320-member update group (sealed scrapes: zero fallback peers, one
shared group id); the comparison cell keeps `per_client_best = true`
on all 320 members and the control keeps it off.

### F = 0.1

| Cell | Root | Completion p50/p95, reload 1 (s) | Completion p50/p95, reloads 2–4 (s) | Stall p50, reload 1 (ms) | Stall p50, reloads 2–4 (ms) | Sampler RSS peak (MiB) |
|---|---|---|---|---|---|---|
| rustbgpd SIGHUP (grouped per-client best) | A2 | 2.2 / 2.3 | 3.3 / 3.5 | 481 | 1,734 | 1,972 |
| rustbgpd SIGHUP (grouped per-client best) | B2 | 2.1 / 2.1 | 3.3 / 3.4 | 509 | 1,806 | 1,996 |
| grouped control (diagnostic) | A2 | 1.9 / 2.0 | 4.4 / 4.5 | 167 | 2,718 | 1,985 |
| grouped control (diagnostic) | B2 | 1.9 / 1.9 | 4.3 / 4.4 | 160 | 2,595 | 1,970 |
| BIRD 3.3.1 (`birdc configure`) | A2 | 12.2 / 13.0 | 11.9 / 13.0 | 813 | 922 | 1,375 |
| BIRD 3.3.1 (`birdc configure`) | B2 | 12.5 / 13.5 | 11.5 / 12.9 | 744 | 985 | 1,377 |
| OpenBGPD 9.1 (`bgpctl reload`) | A2 | 60.1 / 60.1 | 56.3 / 56.3 | 360 | 417 | 1,392 |
| OpenBGPD 9.1 (`bgpctl reload`) | B2 | 62.7 / 62.7 | 57.7 / 57.7 | 351 | 418 | 1,133 |

### F = 0.5

| Cell | Root | Completion p50/p95, reload 1 (s) | Completion p50/p95, reloads 2–4 (s) | Stall p50, reload 1 (ms) | Stall p50, reloads 2–4 (ms) | Sampler RSS peak (MiB) |
|---|---|---|---|---|---|---|
| rustbgpd SIGHUP (grouped per-client best) | A4 | 2.3 / 2.4 | 3.7 / 3.8 | 722 | 2,089 | 2,057 |
| rustbgpd SIGHUP (grouped per-client best) | B4 | 2.2 / 2.3 | 3.5 / 3.6 | 757 | 1,996 | 2,098 |
| grouped control (diagnostic) | A3 | 1.9 / 2.0 | 4.4 / 4.5 | 158 | 2,705 | 2,052 |
| grouped control (diagnostic) | B3 | 1.9 / 2.0 | 4.4 / 4.5 | 155 | 2,658 | 2,019 |
| BIRD 3.3.1 (`birdc configure`) | A4 | 13.1 / 13.8 | 12.4 / 13.6 | 891 | 837 | 1,420 |
| BIRD 3.3.1 (`birdc configure`) | B4 | 12.7 / 13.8 | 11.8 / 13.0 | 936 | 812 | 1,415 |
| OpenBGPD 9.1 (`bgpctl reload`) | A4 | 62.4 / 62.4 | 58.1 / 58.1 | 368 | 427 | 1,313 |
| OpenBGPD 9.1 (`bgpctl reload`) | B4 | 62.7 / 62.7 | 58.5 / 58.5 | 364 | 425 | 1,439 |

Root labels carry the reruns' suffixes (A2/B2, A4/A3/B3/B4); the
superseded earlier roots are disclosed under the defect arc below.
Every row: 320/320 sessions up at reload validation, zero parse
errors. Reading the tables honestly:

- **The per-client-best overlap penalty is gone.** Ungrouped
  per-client best paid ~87 s (F = 0.1) to ~135–143 s (F = 0.5)
  steady-state completion p50 in the sealed baseline; grouped
  per-client best pays 3.25–3.38 s and 3.46–3.77 s (per-reload p50
  range, reloads 2–4) — a ~26× / ~38× reduction, delivered while the
  received views stay byte-identical. The residual F-sensitivity
  (~0.2–0.4 s from F = 0.1 to F = 0.5) is consistent with the design's
  one-extra-evaluation-per-overlapped-prefix pricing, and no term
  scales with member count.
- **rustbgpd's reload completion class changes outright.** The
  grouped per-client-best cell completes below BIRD (~11.5–13.6 s) and
  OpenBGPD (~56–59 s) at both overlap points — the sealed baseline had
  it slower than both at F = 0.5. BIRD and OpenBGPD hold the same
  completion classes they held at zero overlap and in the sealed
  baseline, as expected: nothing changed for them.
- **RSS lands in the grouped class.** Sampler RSS peak is
  1,972–2,098 MiB across the four grouped per-client-best cells,
  against 10,534–11,315 MiB for the sealed ungrouped rows — a
  5.28–5.50× reduction (within-overlap-point pairings) — and
  indistinguishable from the grouped control's 1,970–2,052 MiB.
- **The grouped per-client-best cell runs ahead of its own
  diagnostic control** (steady-state completion p50 3.3–3.8 s vs
  4.3–4.5 s; commit fan-out 1.8–2.2 s vs 2.8–3.0 s, below). The
  direction is consistent across all eight rustbgpd cells. This
  receipt reports the difference and does not attribute it; the gate
  only required landing in the control's class.
- **The first-reload-cheap pattern reproduces** in every rustbgpd
  cell (completion p50 2.1–2.3 s at reload 1 vs 3.3–3.8 s after;
  control 1.9 s vs 4.3–4.5 s), as it did in every prior campaign at
  this shape.

## The acceptance gate, measured

ADR-0126's committed targets, quoted verbatim:

> From the sealed realistic-mix receipt, at the canonical 320 × 183,040
> shape, F ∈ {0.1, 0.5}:
>
> - **Equivalence:** byte-identical per-member received views versus today's
>   ungrouped per-client-best path — every runner-up pair (18,304 / 91,520)
>   delivered, nothing else — proven by the received-view-delta verifier and
>   the extended differential oracle.
> - **Cost:** ≥4× sampler RSS-peak reduction versus the sealed per-client
>   rows (10.4–11.3 GiB), and steady-state reload completion p50 in the
>   grouped-control class (~4.5 s ceiling); the one-extra-evaluation overlap
>   term must not move completion out of that class at F = 0.5.

Measured against each prong:

| Prong | Target | Measured | Verdict |
|---|---|---|---|
| Equivalence: received views | byte-identical vs the ungrouped path; every runner-up pair delivered, nothing else | all four comparison roots' received views bit-identical to the sealed baseline captures (digests above); received-view-delta verifier `pass` with exactly 18,304 / 91,520 suppressed runner-up pairs, both repeats, both overlap points | **PASS** |
| Equivalence: differential oracle | extended oracle proves identical per-member streams | the grouped-vs-forced-ungrouped oracle suite, extended to overlapping per-client-best fleets before the classifier flip, is green in the workspace test suite at the measured commit | **PASS** |
| Cost: sampler RSS peak | ≥4× reduction vs 10.4–11.3 GiB | 1,972–2,098 MiB vs 10,534–11,315 MiB: 5.28–5.41× at F = 0.1, 5.30–5.50× at F = 0.5 | **PASS** (≥5.2×) |
| Cost: completion class | steady-state completion p50 in the grouped-control class (~4.5 s ceiling), including at F = 0.5 | 3.25–3.38 s (F = 0.1) and 3.46–3.77 s (F = 0.5) per-reload steady-state p50 — inside the class at both points, below the control's own 4.26–4.55 s rows | **PASS** |

Both prongs of the Decision 9 rendered-default condition therefore
hold, so `rs-config-render` fleets group at ship with
`path_hiding = true` retained. The confirming evidence is in the
sealed cells themselves: the comparison cell's config is rendered by
the production `rs-config-render` pipeline with path hiding on — the
verifier checks exactly 320 `per_client_best = true` members — and the
sealed scrapes prove that configuration forms one 320-member update
group with zero fallback peers and a runner-up lane equal to the
manifest allocation.

## Reload-phase attribution

The sealed baseline published an unattributed span between "config
source loaded" and "resolved live peer policy chains" — present only
in per-client-best mode, absent at reload 1, scaling with F: 26.9–29.0 s
(F = 0.1) and 66.2–70.7 s (F = 0.5) at reloads 2–4. In this campaign
that span is gone. SIGHUP-to-"partitioned resolved policy snapshot"
offsets across all 32 reloads — both modes, both overlap points, every
reload:

| Cell class | Reload 1 (s) | Reloads 2–4 (s) |
|---|---|---|
| grouped per-client best (all four cells) | 1.40–1.47 | 1.38–1.54 |
| grouped control (all four cells) | 1.40–1.47 | 1.42–1.49 |

Flat across F, flat across reloads, and indistinguishable between the
two modes: the per-client-best-only, reload-2-onward, F-scaling
fingerprint the baseline bounded no longer exists on this path. The
commit fan-out ("committed partitioned resolved policy snapshot") is
0.53–0.71 s at reload 1 and 1.75–2.15 s at reloads 2–4 in grouped
per-client-best mode — against 111.3–145.4 s per reload ungrouped in
the sealed baseline — and 0.37–0.39 s / 2.79–3.01 s in the grouped
control, matching that control's sealed-baseline values.

## The defect arc: four halted roots, three fixes, preserved

This campaign's F = 0.5 comparison cell failed four times before it
passed, and the campaign's first attempt had already exposed a
separate defect at F = 0.1 — three distinct daemon defects on the new
grouped per-client-best path in all. Every root is preserved immutable
per the campaign protocol (no rerun-in-place — each fix got fresh
roots), and each fix commit is in the measured commit's direct
lineage.

1. **Per-member authoritative handoff** (exposed by the first
   attempt's F = 0.1 roots at `f9099f21`, green but slow). The
   campaign's first container ran comparison-A and grouped-A at
   F = 0.1: all gates green, but grouped per-client-best completion
   p50 was 140.0–147.9 s — *worse* than the ungrouped baseline. The
   authoritative export-policy handoff declined the optimized clean
   transition for per-client-best groups and then handed each member
   to the RIB one command at a time, each draining as a full-table
   clone-walk, probe, and encode: 320 serial full-table resyncs per
   reload. The campaign was paused, the container preserved as-is,
   and the fix (one batched shared RIB transition per source group)
   landed as `93abeda2`. A single-cell F = 0.1 verification root at
   that commit (completion p50 3.45–3.59 s at reloads 2–4) confirmed
   the fix before the campaign restarted in a fresh container.
2. **Cohort-setup deadline starvation** (F = 0.5 comparison roots A
   and B at `93abeda2`, halted). The restarted campaign's F = 0.1
   quad passed — and was itself verifier-green, including the
   received-view delta — but both F = 0.5 comparison roots halted:
   reload 1 ran the full 600 s window with zero observer progress,
   healthy sessions timing out during fleet-wide cohort setup and
   every applied peer rolling back (the sealed daemon logs retain the
   timeout and rollback sequences). Two peer-manager waits starved
   the per-session hot-apply deadlines: an unbounded
   destination-prestage round trip queued behind the reload's
   lane-heavy RIB work — statically dead for a per-client-best source
   group — and readiness-query servicing wall-clock-deducted from an
   in-flight session command's budget. The fix (skip the statically
   dead prestage; accrue session deadlines only while the actor is
   driving the round trip) landed as `70ec76dc`.
3. **Per-member derived-view scans** (F = 0.5 comparison roots A2
   and B2 at `70ec76dc`, halted with the same signature). At high
   overlap, every distribution pass asked each member's derived-view
   queries to scan the whole runner-up lane and denial residue while
   filtering for the pass's few staged prefixes — tens of millions of
   map visits per churn pass — leaving the RIB actor oversubscribed;
   separately, an authoritative batch whose caller had already
   abandoned the reply could apply after the reload rolled back. The
   fix (iterate whichever side is smaller, probing the residue per
   staged prefix on the churn hot path; skip and log orphaned
   batches) landed as `aa022e18` — the measured commit.

At `aa022e18` the F = 0.5 comparison cell passed on its first two
runs (A3/B3, sealed in-gate and with received views byte-identical to
the baseline). Those two ran back-to-back rather than interleaved with
the grouped roots, so a fresh strict-order A/B/B/A quad (A4, grouped
A3/B3, B4) was run for the verified set; the campaign verifier
rejected both non-conforming intermediate sets — the mixed-commit
F = 0.5 set ("four roots do not share commit") and the back-to-back
set ("roots are not in strict A/B/B/A execution order") — and those
rejection outputs are preserved alongside the roots. The F = 0.1 quad
and the F = 0.5 grouped controls were likewise rerun at `aa022e18`
solely for commit uniformity; the superseded `93abeda2`-era green
roots (F = 0.1 quad, F = 0.5 grouped A/B) and the `aa022e18`-era
superseded pairs (F = 0.5 comparison A3/B3, grouped A2/B2) all remain
sealed in the campaign archive.

## Method

Everything is the sealed realistic-mix receipt's protocol, unchanged:
the canonical 320-member × 183,040-prefix shape (3,218,965 IRR filter
entries, seed 61, 4 reloads per cell), the announcement-overlap model
at F ∈ {0.1, 0.5} with its documented limits, dataset determinism
pinned by `dataset_sha256` (digests identical to the sealed
baseline's, so both campaigns filtered byte-identical datasets), four
fresh sealed read-only roots per overlap point in counterbalanced
comparison/grouped/grouped/comparison order, fresh daemon identity
per cell, quiet-host gates, 300 s cool-downs, one harness and one
receiver-side instrument, each daemon reloading by its
operator-documented mechanism. Metric definitions are identical to
the [IRR reload comparison](irr-reload-comparison-2026-08.md) and the
[`bench/scale/irrreload/`](../../bench/scale/irrreload/README.md)
README. What changed since the baseline is the daemon under test —
the ADR-0126 classifier now groups the per-client-best fleet — and
the harness's topology gates, which since the flip require both
rustbgpd cells to form exactly one 320-member update group and pin
the runner-up lane gauge to the manifest's overlap allocation
(comparison cell) or zero (grouped control).

## Honesty notes

- Loopback TCP on one host; one shape, two repeats per cell class per
  overlap point in fixed counterbalanced order — not statistically
  independent trials.
- This campaign ran at `aa022e18`; the sealed ungrouped baseline ran
  at `0eaaea16`. Per that receipt's own convention the cross-campaign
  rows are not exact-tag comparable, and the flat daemons (BIRD,
  OpenBGPD) landing in their baseline completion classes is
  consistency evidence, not a same-commit A/B. Two additional
  cross-checks tighten this one: the received views are byte-identical
  across the two campaigns (an exact cross-commit equivalence check),
  and two pre-flip single-cell confirmation roots at the same shape
  (2026-08-07, commit `871ae0a1` — after the intervening fix wave,
  before the classifier flip) still measured the *ungrouped*
  per-client-best path at 79.0–79.7 s (F = 0.1) and 129.5–129.9 s
  (F = 0.5) steady-state completion p50, so the class change measured
  here belongs to grouping, not to unrelated drift between the two
  receipts' commits.
- The eight verified roots are single-commit, but the campaign was
  not: the defect arc above spans four commits, and the intermediate
  roots — including a fully verifier-green F = 0.1 quad at
  `93abeda2` — are preserved rather than folded into the receipt. The
  verified set was chosen for commit uniformity and strict execution
  order, not because the superseded green roots disagree (they do
  not: the `93abeda2` F = 0.1 quad's rows and received-view delta
  match the final set's within run-to-run spread).
- All four non-passing roots were daemon defects on the new grouped
  path, not environment; no environmental red occurred in this
  campaign (the sealed baseline's default-route-flap hazard did not
  recur).
- The grouped per-client-best cell outrunning the grouped control is
  reported above as an observation with no attributed cause and no
  claim.
- The received-view equivalence is against the sealed baseline's
  captures over the same sealed scenario; it proves the grouped walk
  delivers what the ungrouped walk delivered, under a model where
  every overlapped prefix has exactly one runner-up — not the
  operational value of any particular hidden path.
- SIGHUP + `.rpol` swap re-parses only the policy files; `birdc
  configure` and `bgpctl reload` re-parse the entire config — each
  daemon's documented reload operation, not the same amount of work.
- The grouped-control rows price the path-hiding seam for the same
  daemon and dataset; they are not a competitor configuration.
- Filter-list padding entries are all /24s; real IRR lists mix
  lengths. Constant across daemons, generations, and overlap points.

## Provenance

- **Commit measured**: `aa022e18c14fc8e2cf6ec23f9ba88d9e0c090042` —
  clean, exactly `origin/main` at run time for all eight verified
  roots (includes the full ADR-0126 implementation and the three
  defect fixes above). Defect-arc root commits:
  `f9099f218ef2` (first attempt), `93abeda2445a`, `70ec76dc0535`;
  pre-flip confirmation roots at `871ae0a13c3c`.
- **Dataset digests** (identical across all four cells at each
  overlap point, and identical to the sealed baseline's):
  - F = 0.1: `473482bc7c485f10d5cbb38c7adfbe8db74e4789cfc38525c6344d3732345eba`
  - F = 0.5: `16fcfb4d5fb5a4b2c5a578c0e7e66943c2935e2ad51ae8c897eb675cedd3f2bb`
- **Independent verification**: `verify-receipt.py campaigns` over
  each four-root verified set returned `status: "pass"` — 24
  comparison rows and 8 grouped-control rows per overlap point
  re-derived, root order, seals, process identities, provenance
  fingerprints, dataset digests, post-flip topology gates, and the
  received-view delta all validated; the standalone
  `received-view-delta` verifier passed for both A/B repeats at both
  overlap points with identical counts. Verifier outputs are
  committed in
  [`artifacts/irr-reload-grouped-per-client-best-2026-08/`](artifacts/irr-reload-grouped-per-client-best-2026-08/README.md);
  every number in this document traces to a row in those CSVs, a
  committed verifier JSON, the received-view digests, or the sealed
  daemon logs (phase spans).
- **Per-root provenance fingerprints** (schema-3, re-derived by the
  verifier):

  | Root | Fingerprint |
  |---|---|
  | F = 0.1 comparison-A2 | `ec58c3a2e4d62afed4ec3460bca2da163e86636d3cda97bc845f45a1971db25b` |
  | F = 0.1 grouped-A2 | `c9170e320f6fa44f097471c9359d1be27d03c7ec984e1d8e1d8ee540294d5b77` |
  | F = 0.1 grouped-B2 | `1f64e8c718875637ad18d651bf4ca06008478e5ae7ba9db09c298aad913a6b80` |
  | F = 0.1 comparison-B2 | `9ad1a06639f50ee84160120de6dd0bad8e714e25e017e2ce70309980ecb774f2` |
  | F = 0.5 comparison-A4 | `b9c15371f649182086567d23ce76d905c1b9ad8be22cf000fe1e6ff00c2adf2d` |
  | F = 0.5 grouped-A3 | `3496e9bef61b1b7f9d33d9d76e6874b5f08e4084573156cfd581b2d1ef67bac2` |
  | F = 0.5 grouped-B3 | `a581c6474e1d5161f25fe32e74ce443d0321119ec53510aa54f17b2c84aa38a3` |
  | F = 0.5 comparison-B4 | `180563c318cde586b8b46ebee2dec46246edc7a8bbe52c8b50eb0b9513d7d85e` |

- **Peer images**: `bird:3.3.1` (built from
  `tests/interop/Dockerfile.bird3`) and `openbgpd/openbgpd:9.1`.
- **Sealed evidence**: the eight verified roots, the four halted
  roots, the superseded green roots (both containers), the single-cell
  fix-verification root, and the pre-flip confirmation roots (daemon
  logs, RSS streams, received views, manifests, quiet samples, seals,
  verifier rejection outputs) are retained read-only in the campaign
  artifact archive, off-repo. Recognize the verified originals by
  their seal digests:

  | Root | `SHA256SUMS` seal digest | `COMPLETED` digest |
  |---|---|---|
  | F = 0.1 comparison-A2 | `14507e87eef0ed9a0357c967817c83f69c564e0a62e8bf1f2edde24a70e134ea` | `62d0e13764a6f02d28ff292c7fe48fd5485866b45f529f265135adf43f7accaf` |
  | F = 0.1 grouped-A2 | `73d7b170ba2ca5518f4d4a9147d147236474863091e734ac2ad3a7c51c693a44` | `507601b450d5abdaef403c4e7e4d5aa4810d333ce06fc154f3d7f69293368375` |
  | F = 0.1 grouped-B2 | `528608f0ed43fe6db3f54a8cb65a5fd5586d6bd4968b0ef2e5a0a6a9dcd2691f` | `e7776ed4a3b27ba4bbafa828aa4fa821c7d710ce7387559945937f20a09b129f` |
  | F = 0.1 comparison-B2 | `9e2a64d01306d75082477a8d117b281669fff0d61ed74e51459c4bd5f7d30c33` | `3f4ddbee975f62cfea588e28141922121e62629084fce616241968f7c82599c3` |
  | F = 0.5 comparison-A4 | `bf2ce3fe3a7abd0977840e820933b25dfa33451f3801934318c0f974b67afc2d` | `5b42d09f726be1f9daa4f64061184f395754f52e07bdb8d7862d750d3989d6a6` |
  | F = 0.5 grouped-A3 | `dd862d538574a0488436cdc2ebea186c34761177c192630b2b72e1c89f82c3c2` | `e4083454320e8c9e9afa4ea90b6da5c07942be67c9c69460bd41f35c1d0b1af8` |
  | F = 0.5 grouped-B3 | `00873dc25d1bcd142214cff6867469ea2e9ada4637d23387dd38515db3bba874` | `ffad5c5f899bfe16f3cbf0f17959c0cc65df3e6687b4721c31a16ca7c3fea64e` |
  | F = 0.5 comparison-B4 | `8d174da9737870e19adca3878e7274acf62a343cf97fb002f50e3bf5e9bbd2fb` | `c31c5839be8d9e316fc6a783f616a9b52856e1595a14844dfca02d5a9381caef` |

## Environment

| Field | Value |
|---|---|
| Hardware | AMD Ryzen Threadripper 7970X (32 cores), 125 GiB RAM |
| Kernel | Linux 6.17.0-35-generic x86_64 |
| Toolchain | rustc 1.97.0, cargo 1.97.0, Python 3.12.3, Docker 29.2.1 |
| Build | `--release`; quiet-host gates as in the harness README |

## Reproduction

The campaign runner, overlap model, protocol, post-flip topology
gates, and verifier are
[`bench/scale/irrreload/`](../../bench/scale/irrreload/README.md).
This receipt reproduces with the documented `OVERLAP_FRACTION`
four-root invocation sequence at each sensitivity point, followed by
the `verify-receipt.py campaigns` and
`verify-receipt.py received-view-delta` steps; the byte-identity
check is a `cmp` of each comparison root's
`rustbgpd-sighup/received-view.tsv` against the sealed realistic-mix
baseline capture at the same overlap point and repeat.
