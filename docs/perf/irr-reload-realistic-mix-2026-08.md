# Realistic-mix IRR reload receipt — announcement overlap — 2026-08

What does per-client best-path — the path-hiding mitigation a route
server runs so each member sees the best route computed *without its
own announcements hidden by a shared RIB* — actually cost and deliver
when member announcements overlap the way real route-server tables do?
The canonical [IRR reload comparison](irr-reload-comparison-2026-08.md)
answers the reload-cost question at zero overlap, where per-client
best-path and grouped export are behaviorally identical by
construction. This receipt makes the comparison real: the same
320-member × 183,040-prefix shape (3,218,965 IRR filter entries, 4
reloads per cell, all sessions up), with an announcement-overlap
dimension that gives a seeded fraction `F` of base prefixes exactly one
second announcing member. Two sensitivity points — `F = 0.1` and
`F = 0.5` — bracket the published evidence on route-server path
diversity (see Method). Eight fresh sealed artifact roots, four per
overlap point in counterbalanced A/B/B/A order, all green,
cross-checked by the campaign's independent verifier; one
environmental red root preserved and disclosed below.

## What the mitigation delivers: the received-view delta

The headline observable is counted on the wire, observer-side, with no
daemon gauge involved: after the final measured reload, each of the
320 live observer stubs dumps its final-generation received view, and
the verifier compares the per-client-best and grouped cells' views
over the same sealed scenario.

| Overlap F | Overlapped (member, prefix) pairs allocated | Runner-up pairs delivered by per-client best and suppressed by grouped export |
|---|---|---|
| 0.1 | 18,304 | **18,304** |
| 0.5 | 91,520 | **91,520** |

The verifier enforces three properties, and both A/B repeats at both
overlap points pass identically: grouped deliveries are a pointwise
subset of per-client-best deliveries; every delta pair is an
overlapped prefix observed at one of its announcers; and the total
equals the scenario manifest's overlap allocation exactly — one
suppressed best-path announcer per overlapped prefix. In other words,
per-client best-path delivered precisely the alternative paths the
overlap model says a shared-RIB export would hide, and nothing else.

## What it costs: cross-daemon comparison

Wire-observed, receiver-side, percentiles across all 320 observers.
r2–4 columns are the mean of reloads 2–4 (the steady-state
generations); reload 1 is listed separately because the
first-reload-cheap pattern from the canonical receipt reproduces here.
Stall = `all_observer_maxgap_p50_ms`. RSS = per-cell peak of the 5 s
process-tree sampler, the only cross-daemon RSS instrument (it can
double-count shared mappings; close differences are not exact
allocator comparisons). The grouped-control rows are the standalone
path-hiding diagnostic — never a competitor configuration — and are
included here to price the seam, per the harness protocol.

### F = 0.1

| Cell | Root | Completion p50/p95, reload 1 (s) | Completion p50/p95, reloads 2–4 (s) | Stall p50, reload 1 (ms) | Stall p50, reloads 2–4 (ms) | Sampler RSS peak (MiB) |
|---|---|---|---|---|---|---|
| rustbgpd SIGHUP (per-client best) | A2 | 57.2 / 107.0 | 87.5 / 139.5 | 318 | 19,860 | 10,659 |
| rustbgpd SIGHUP (per-client best) | B | 59.0 / 110.6 | 87.1 / 138.7 | 318 | 17,053 | 10,534 |
| grouped control (diagnostic) | A | 1.7 / 1.8 | 4.5 / 4.5 | 165 | 2,896 | 1,988 |
| grouped control (diagnostic) | B | 1.7 / 1.8 | 4.5 / 4.5 | 187 | 2,896 | 1,998 |
| BIRD 3.3.1 (`birdc configure`) | A2 | 12.0 / 13.0 | 12.3 / 13.3 | 879 | 818 | 1,386 |
| BIRD 3.3.1 (`birdc configure`) | B | 12.1 / 13.6 | 12.1 / 13.0 | 841 | 927 | 1,382 |
| OpenBGPD 9.1 (`bgpctl reload`) | A2 | 61.2 / 61.2 | 58.0 / 58.0 | 376 | 430 | 1,316 |
| OpenBGPD 9.1 (`bgpctl reload`) | B | 63.3 / 63.3 | 59.1 / 59.1 | 391 | 438 | 1,241 |

The F = 0.1 comparison roots are labeled A2/B because the first
comparison-A attempt is the preserved environmental red disclosed
below; A2 is its fresh redo.

### F = 0.5

| Cell | Root | Completion p50/p95, reload 1 (s) | Completion p50/p95, reloads 2–4 (s) | Stall p50, reload 1 (ms) | Stall p50, reloads 2–4 (ms) | Sampler RSS peak (MiB) |
|---|---|---|---|---|---|---|
| rustbgpd SIGHUP (per-client best) | A | 71.0 / 132.8 | 143.0 / 204.9 | 376 | 43,064 | 11,315 |
| rustbgpd SIGHUP (per-client best) | B | 68.4 / 127.7 | 135.2 / 194.6 | 372 | 47,126 | 11,113 |
| grouped control (diagnostic) | A | 1.7 / 1.8 | 4.5 / 4.6 | 176 | 2,947 | 2,042 |
| grouped control (diagnostic) | B | 1.7 / 1.8 | 4.6 / 4.7 | 155 | 2,986 | 2,109 |
| BIRD 3.3.1 (`birdc configure`) | A | 13.6 / 14.3 | 12.8 / 14.0 | 863 | 808 | 1,414 |
| BIRD 3.3.1 (`birdc configure`) | B | 12.3 / 13.7 | 12.1 / 13.3 | 836 | 823 | 1,416 |
| OpenBGPD 9.1 (`bgpctl reload`) | A | 67.3 / 67.3 | 64.5 / 64.5 | 384 | 449 | 1,491 |
| OpenBGPD 9.1 (`bgpctl reload`) | B | 64.5 / 64.5 | 59.6 / 59.6 | 370 | 450 | 1,427 |

Every row: 320/320 sessions up at reload validation, zero parse
errors. Reading the tables honestly:

- **Overlap scales rustbgpd's per-client reload cost and nobody
  else's.** Per-client steady-state completion p50 is ~87 s at
  F = 0.1 and ~135–143 s at F = 0.5. BIRD sits at ~12–13 s and
  OpenBGPD at ~58–65 s at *both* overlap points — the same completion
  classes they hold at zero overlap — and the grouped control holds
  ~4.5 s at both. The overlap dimension isolates a per-client-best
  cost that grows with F.
- **The steady-state per-client stall is the same story**: reload
  stall p50 at reloads 2–4 is ~17–20 s (F = 0.1) and ~43–47 s
  (F = 0.5) for per-client best, against ~2.9–3.0 s grouped, sub-second
  BIRD, and sub-half-second OpenBGPD. The phase attribution below
  locates this span.
- **Priced against the grouped control** (same daemon, dataset, and
  reload mechanism): the mitigation costs roughly 19× steady-state
  completion p50 at F = 0.1 and roughly 30× at F = 0.5, and ~5×
  sampler RSS peak (~10.5–11.3 GiB vs ~2.0–2.1 GiB). That is the price
  of delivering the 18,304 / 91,520 runner-up pairs above.
- **The first-reload-cheap pattern reproduces** in every per-client
  cell (completion p50 ~57–71 s at reload 1 vs ~87–143 s after; stall
  p50 ~0.3–0.4 s vs ~17–47 s) and in the grouped control (~1.7 s vs
  ~4.5 s). Its cause is bounded by the phase attribution below.

## Reload-phase attribution

The reload span instrumentation decomposes each SIGHUP reload
daemon-side. Across all 32 rustbgpd reloads in this campaign — both
modes, both overlap points, every reload — the instrumented phases
are flat:

| Instrumented phase | Range across all 32 reloads |
|---|---|
| interned rpol set tables built | 335–524 ms |
| config source loaded (total) | 753–972 ms |
| — of which `toml_parse` | 0–2 ms |
| — of which `rpol_load` | 362–468 ms |
| — of which `validate` | 391–580 ms |
| — of which `dataset_bind` | 0 ms |
| resolved live peer policy chains (320 peers) | 71–87 ms |

None of these scales with F, and none differs between reload 1 and
the later reloads. The steady-state plateau is therefore **not**
parse, set interning, dataset binding, validation, or chain
resolution. What remains is an unattributed span between "config
source loaded" and "resolved live peer policy chains", present only in
per-client-best mode, absent at reload 1, and scaling with F
(SIGHUP-to-"partitioned resolved policy snapshot" offsets, seconds):

| Cell | Reload 1 | Reload 2 | Reload 3 | Reload 4 |
|---|---|---|---|---|
| F = 0.1 per-client best, root A2 | 1.20 | 26.9 | 29.0 | 28.7 |
| F = 0.1 per-client best, root B | 1.33 | 28.4 | 28.5 | 27.5 |
| F = 0.5 per-client best, root A | 1.23 | 70.3 | 70.6 | 70.7 |
| F = 0.5 per-client best, root B | 1.21 | 66.2 | 67.7 | 67.1 |
| grouped control (all four cells) | 1.23–1.34 on every reload |

This span is **under investigation**. The fingerprints published here
bound it — per-client-best-only, reload-2-onward-only, F-scaling,
upstream of the commit fan-out — and this receipt does not speculate
past them.

The commit fan-out ("committed partitioned resolved policy snapshot")
is separately timed and roughly constant across reloads within a
cell: 111.3–120.5 s per reload at F = 0.1 and 133.0–145.4 s at
F = 0.5 in per-client-best mode, versus 0.36–0.39 s (reload 1) and
3.0–3.2 s (reloads 2–4) in the grouped control. Instrument note: boot
logs carry no "config source loaded" span because the boot-time
config load precedes tracing initialization; only reload-path loads
are stamped, which is the population measured here.

## Environmental red root, preserved

The first F = 0.1 comparison attempt went red and is preserved
immutable: during its OpenBGPD cell, reload 2 stalled with zero
observer progress for the full 600 s window. Root cause, from the
daemon logs and the host journal: between reload 1 completion and the
reload 2 trigger, the host's DHCP-managed IPv4 default route was
replaced (identical-route delete/re-add pairs, twice). OpenBGPD —
running the documented `nexthop qualify via default` route-server
posture with `fib-update no` — marked all 640 stub nexthops invalid
immediately after the flap and never re-qualified them even though the
kernel retained a default route, so reload 2 legitimately had no
eligible routes to re-advertise (both reloads reached "RDE soft
reconfiguration done"). The host journal shows such replace pairs
recurring at irregular intervals for days: a host-environment fault
that violates the harness's default-route precondition, independent of
the overlap dimension and of any daemon's measured behavior. Per the
immutable-root protocol, no cell was rerun into the existing root; the
red root was sealed as-is with its diagnostic context and the
comparison root redone fresh. The remaining OpenBGPD cells ran between
flaps and passed their quiet gates.

## Method

- **Overlap model.** The canonical scenario announces disjoint
  per-member slices, so the Loc-RIB never holds two candidate paths
  and per-client best-path has nothing to deliver. With
  `OVERLAP_FRACTION=F`, `round(F × 183,040)` base prefixes — drawn
  under a seed-derived RNG stream — each gain exactly one second
  announcing member, drawn uniformly from the other members; the
  second announcer's filter lists admit the prefix in both policy
  generations, and the allocation is recorded in the scenario
  manifest. Model limits, stated plainly: every overlapped prefix has
  exactly two announcers (real route servers see heavier tails), the
  second announcer is uniform over members (real overlap concentrates
  in large members), and both paths are equal-preference single-hop
  routes decided by daemon tie-break.
- **Choosing F.** Public evidence on how much of a route server's
  table is announced by two or more members is thin. The one published
  point estimate: an ACM SIGCOMM 2025 poster crawling Alice Looking
  Glass snapshots at 16 major IXPs reports that at one of the largest
  European IXPs roughly 50% of prefixes have alternative paths
  (Alhamwy, Khoulani, Hohlfeld, "POSTER: Crawling Alice Looking
  Glasses at IXPs to Quantify BGP Route Diversity", ACM SIGCOMM 2025
  Posters and Demos, doi:10.1145/3744969.3748457); the path-hiding
  mechanism itself is documented in Richter et al., "Peering at
  Peerings: On the Role of IXP Route Servers" (IMC 2014). Because that
  50% figure is a poster-stage measurement of one IXP, this campaign
  runs a sensitivity pair rather than blessing a single value:
  F = 0.1 as a conservative low-diversity bound and F = 0.5 as the
  published large-IXP point estimate.
- **Seed determinism.** Dataset generation is fully deterministic
  from shape + seed (seed 61 throughout); the manifest carries a
  canonical `dataset_sha256` and the campaign rejects any cell whose
  digest differs, so all four cells at an overlap point filter
  byte-identical datasets. `F = 0` reproduces the historical generator
  output byte-for-byte.
- **Everything else is the canonical protocol** of the
  [IRR reload comparison](irr-reload-comparison-2026-08.md) and the
  [`bench/scale/irrreload/`](../../bench/scale/irrreload/README.md)
  README: four fresh sealed read-only roots per overlap point in
  counterbalanced comparison/grouped/grouped/comparison order, fresh
  daemon identity per cell, quiet-host gates with the recurring bench
  schedule disabled, 300 s cool-downs, one harness and one
  receiver-side instrument, each daemon reloading by its
  operator-documented mechanism at its documented route-server
  configuration. Metric definitions are identical to the canonical
  receipt.

## Honesty notes

- Loopback TCP on one host; one shape, two repeats per cell class per
  overlap point in fixed counterbalanced order — not statistically
  independent trials.
- This campaign ran at a later commit than the canonical F = 0
  receipt, so its rows are not exact-tag comparable with that
  document's; the flat-across-F daemons (BIRD, OpenBGPD) landing in
  the same completion classes as at F = 0 is consistency evidence,
  not a same-commit A/B.
- The received-view delta counts delivered runner-up *pairs* under a
  model where every overlapped prefix has exactly one runner-up; it
  measures that the mitigation delivers what the model hides, not the
  operational value of any particular hidden path.
- SIGHUP + `.rpol` swap re-parses only the policy files; `birdc
  configure` and `bgpctl reload` re-parse the entire config — each
  daemon's documented reload operation, not the same amount of work.
- The grouped-control rows price the path-hiding seam for the same
  daemon and dataset; they are not a competitor configuration, and
  the cross-daemon reading above never rests on them.
- During one green root's OpenBGPD quiet gate, a swap-activity sample
  pair was retaken once (logged); the gate then passed.
- Filter-list padding entries are all /24s; real IRR lists mix
  lengths. Constant across daemons, generations, and overlap points.

## Provenance

- **Commit measured**: `0eaaea16d041cfa23f92f16a52d7d1d24a1d05de` —
  clean, exactly `origin/main` at run time for all eight green roots
  (includes the announcement-overlap harness dimension and the
  reload-span decomposition instrumentation).
- **Dataset digests** (identical across all four cells at each
  overlap point; the two differ because the overlap allocation is
  part of the dataset):
  - F = 0.1: `473482bc7c485f10d5cbb38c7adfbe8db74e4789cfc38525c6344d3732345eba`
  - F = 0.5: `16fcfb4d5fb5a4b2c5a578c0e7e66943c2935e2ad51ae8c897eb675cedd3f2bb`
- **Independent verification**: `verify-receipt.py campaigns` over
  each four-root set returned `status: "pass"` — 24 comparison rows
  and 8 grouped-control rows per overlap point re-derived, root order,
  seals, process identities, provenance fingerprints, dataset digests,
  and the received-view delta all validated; the standalone
  `received-view-delta` verifier passed for both A/B repeats at both
  overlap points with identical counts. Verifier outputs are committed
  in
  [`artifacts/irr-reload-realistic-mix-2026-08/`](artifacts/irr-reload-realistic-mix-2026-08/README.md);
  every number in this document traces to a row in those CSVs, a
  committed verifier JSON, or the sealed daemon logs (phase spans).
- **Per-root provenance fingerprints** (schema-3, re-derived by the
  verifier):

  | Root | Fingerprint |
  |---|---|
  | F = 0.1 comparison-A2 | `fec59d02f9b399a744b421f1179285d1bce56041f37761e616ee4027b22fd2db` |
  | F = 0.1 grouped-A | `7f5dce7b92e3974408c66d6f61a24470d8a53e91dbc5360b615ed05df67472d8` |
  | F = 0.1 grouped-B | `b8d3858ed726f2dcd096502c62c656e3470405a1ecdac6b7e9036c439baa991e` |
  | F = 0.1 comparison-B | `e74070335facb58e8a5de9820aa14a0a2ca761a9dde3cef4d2f438e1f0663b8d` |
  | F = 0.5 comparison-A | `5864a64d2a7a38c2709f2feaab6a7d9f0f67a34e0dfd085c3c89d3bfac0d4ab9` |
  | F = 0.5 grouped-A | `dd1e5066720f3ad26bb349666f1891793154aa02c9e8e80e5cb1c975c605c191` |
  | F = 0.5 grouped-B | `5c020bd3028a9aba9b9de280c6007e0b0508e7ee30e5e6928ca6d673f8e4442e` |
  | F = 0.5 comparison-B | `4e1273a13750c68f4ed1a4f07ddd27daff2269c79da143ff2322b8b15b656193` |

- **Peer images**: `bird:3.3.1` (built from
  `tests/interop/Dockerfile.bird3`) and `openbgpd/openbgpd:9.1`.
- **Sealed evidence**: the eight full green roots plus the preserved
  red root (daemon logs, RSS streams, received views, manifests,
  quiet samples, seals, red-root diagnostic context) are retained
  read-only in the campaign artifact archive, off-repo. Recognize the
  originals by their seal digests:

  | Root | `SHA256SUMS` seal digest | `COMPLETED` digest |
  |---|---|---|
  | F = 0.1 comparison-A2 | `5b799c6d2a33993180dc45acc990ece66536be0b554714053e0a1eb3aeca656b` | `e99c88323c2239c87492405bd516f40dbbd0f41f196c66f60fb5def38da2fc26` |
  | F = 0.1 grouped-A | `8b32688666b4ea58a12b2a06fe71053890275e853be4a9ca033c9aff8f1d5cd3` | `2ed7789339006adbb0059b63b902ab069fd9be58141a05bfbff1d4e5c067a0fc` |
  | F = 0.1 grouped-B | `fd5f8704e93c24a88f0ace13b5fea9dec829cf9c2a3a57289bc2b00228e39af8` | `8cb3aac6fd0f55365490ee4a17363bdbbca09df6573e05f76cdcd56cb03d87c3` |
  | F = 0.1 comparison-B | `bb4ff811046857d5d9fad64bf3bfa086cd8d97beab8d86ef3f6d6e482589065c` | `43558e49162702eaae90cfa0eab1ae510f3879d2def6ee5fd8a1d0bd684c0518` |
  | F = 0.5 comparison-A | `8c0a21df5229b70d8f564f6a60cd2b6a9dcb326faf5ed71bfb5b74d9b59a199d` | `e6c4bdebf247e6fde91e364d4feca20926bdb445ed36bc293ac074e015c8f3f8` |
  | F = 0.5 grouped-A | `65fa895b7443ddffc0cf72aff518a6b6416d8b86bfe1899c82eaba76f8c34217` | `c0cf0fef572cef22e732124f551b9c7f98ea79535e26b62fb4f246ad44da97cc` |
  | F = 0.5 grouped-B | `ccae9a37a3be11f626aa6cb3bd50bb5f33063d457eab1f9006e569ba6b29722b` | `07a95ea3829022c09eaa2eefabbb2937bdd91293e3f5fb88f02ce99fe9936c54` |
  | F = 0.5 comparison-B | `f2895fff87462cafc82fe2654922c0a5e057a352e108106dd28ca671e3899902` | `3964f84b72036e5172559beed0550ea63aa04df2c2fd0dea9816565e597a1961` |

## Environment

| Field | Value |
|---|---|
| Hardware | AMD Ryzen Threadripper 7970X (32 cores), 125 GiB RAM |
| Kernel | Linux 6.17.0-35-generic x86_64 |
| Toolchain | rustc 1.97.0, cargo 1.97.0, Python 3.12.3, Docker 29.2.1 |
| Build | `--release`; quiet-host gates as above |

## Reproduction

The campaign runner, overlap model, protocol, and verifier are
[`bench/scale/irrreload/`](../../bench/scale/irrreload/README.md).
This receipt reproduces with the documented `OVERLAP_FRACTION`
four-root invocation sequence at each sensitivity point, followed by
the `verify-receipt.py campaigns` and
`verify-receipt.py received-view-delta` steps.
