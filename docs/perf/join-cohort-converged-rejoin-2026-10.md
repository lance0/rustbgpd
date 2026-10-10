# Join-cohort converged-rejoin qualification, October 2026

Completing queued same-group joiners from one shared replay cut the slowest
of 50 simultaneous rejoins from 5.972 s to 0.282 s (median of nine rounds) on a
700-member route server whose table stayed converged across the reconnect.
A single rejoin did not regress, and survivors and readiness stayed within
their predeclared limits. The change shipped as #2999 (main `8e1430e49`).

Measured on 2026-10-10 on one host. The [compact receipt](artifacts/join-cohort-converged-rejoin-2026-10/README.md)
retains every cell's harness log, the quiet-host samples and the analyzer that
recomputes the table and verdict below. There are **three fresh daemon
processes per arm and K**, each with three correlated rounds; nine rounds are
not nine independent processes.

## Question

When K members of one update group reconnect to a converged table at the same
time, the control completes their initial-table exports one after another: each
joiner gets its own full replay, export probe and per-session encode on the RIB
actor. The last joiner therefore waits about K replays. The candidate takes
every queued joiner of the same group with an equivalent wire profile, builds
one replay payload and one shared encode, and sends each member its table with
the usual per-member source exclusion and residue.

Does the cohort replay remove that K-fold serialization, without slowing a
single rejoin, starving surviving members or breaking RIB readiness?

## Shape

- 700 identically configured IPv4 route-server members, each with its own
  ASN, and 400,400 disjoint prefixes (572 per member). The last eight members churn a dedicated 16-prefix block
  throughout; they never flap.
- **Converged rejoin with GR helper retention.** Members negotiate Graceful
  Restart (`gr_peer_restart_time_max = 180`, `gr_stale_routes_time = 360`).
  Each round hard-closes K members, waits 10 s, verifies through metrics that
  their routes are still retained, then reconnects them. The Loc-RIB and every
  survivor's table stay unchanged, so the only export work is the joiners'
  initial tables.
- **Observers refreshing.** At two checkpoints per round, before the reconnect
  and after GR settles, two surviving members send an IPv4 ROUTE-REFRESH and
  must receive the exact current table and End-of-RIB. The refresh replays fall
  outside the measured rejoin window.
- K = 1 and K = 50, three rounds per process.

## Arms

| Arm | Source | Daemon sha256 |
|---|---|---|
| Control | main `1d0e4e155d0cf8e42ab007c399067540855c02df`, the commit immediately before #2999 | `47a2c186ba6749c5e27c5a834c8f315e65d64db5a085bb3df8c012ecc707d993` |
| Candidate | `2a9cd95eb11a3431b9ac87f45a4e4ea4773e1871`, a local merge of the control with #2999's final head `1e862f306` | `249fdc1af75a60f96a1adc49cb4de4f684d94013d41c4881de3b9238e8f10896` |

The candidate's source tree (`a49dabbaf7cabf963411c7613ac3e2ca64877c5a`) is
identical to the tree of main `8e1430e49`, the squash merge of #2999, so this
run measured the shipped source. The arms differ by exactly #2999's diff: 12
files, +1295/−60, under `crates/rib`, `crates/transport/benches` and
`changelog.d`. `bench/` and `tests/` are identical, so one harness binary
(`reloadstall`, built at the control with `--profile scale`) and the control's
scenario generator served both arms.

Both daemons were built with `cargo build --release --locked -p rustbgpd --bin
rustbgpd`, Rust 1.99.0. The job re-checked every binary hash before running.

## Method

- One fresh daemon per cell, three repetitions. Repetitions 1 and 3 ran
  control K=1, candidate K=1, candidate K=50, control K=50; repetition 2 ran
  the reverse. Twelve cells, nine rounds per arm and K.
- Before every cell, the shared host lock was held and the quiet-host gate
  (`bench/scale/host-quiet.sh`) retained two accepted samples 30 s apart: load
  below 2.0, every CPU on the `performance` governor, no compiler, benchmark or
  BGP daemon running, and no swap movement.
- The daemon ran on 27 CPUs (12–32 and 34–39; CPU 33 hosts an unrelated busy
  process) and the harness on CPUs 40–63.
- Host: AMD Ryzen Threadripper 7970X (32 cores, 64 threads), 125 GiB RAM, no
  swap configured, Linux 7.0.0-30-generic.

**Clocks.** A joiner's rejoin time runs from its OPEN write to the later of its
End-of-RIB and the moment the harness has seen its exact full table: 399,828
prefixes, every prefix except its own 572. `rejoin_max` is the slowest joiner
in a round. `survivor_maxgap` is the longest interval during the rejoin window
in which some surviving member received no UPDATE; the churners keep updates
flowing, so a starved survivor shows up as a long gap. The harness clocks are
observer timestamps after frame decode, not packet captures.

**Readiness.** Throughout every round the harness polls `/readyz` once per
second and fails the run on any response that is not 200 within 250 ms.

**Validity, failing closed.** Every scheduled cell must have run with harness
and daemon exit 0 after an accepted quiet sample, and must report exactly three
rounds with 700 sessions up, K flapped peers, zero parse errors, readiness
samples taken and finite timings. The harness also exits non-zero on survivor
prefix loss or withdrawal, a session not Established after rejoin, or lost
joiner coverage after GR settles. All 12 cells passed.

## Predeclared bars

Fixed before the run and encoded in the published analyzer:

- **B1 (primary):** at K=50 the candidate's median `rejoin_max` is below the
  control's, and the ranges are disjoint (candidate max < control min).
- **B2:** at K=1 the candidate's median `rejoin_max` is at most the control's
  × 1.10 + 30 ms.
- **B3:** at each K, the candidate's median survivor gap is at most the
  control's × 1.10 + 50 ms, and its maximum at most the control's × 1.10 +
  100 ms.
- **B4:** zero readiness failures.

## Results

Medians are over nine rounds; brackets give the observed range. "Readiness
samples" counts `/readyz` polls, every one of which returned 200 within 250 ms.
RSS is the daemon's `VmRSS` at the end of each round, not a peak.

| Arm | K | `rejoin_max` median [range] | `rejoin_p50` median | Survivor gap median / max | Readiness samples | RSS median |
|---|---:|---:|---:|---:|---:|---:|
| Control | 1 | 0.183 s [0.180–0.187] | 0.183 s | 122.7 / 127.8 ms | 108 | 426 MiB |
| Candidate | 1 | 0.164 s [0.161–0.170] | 0.164 s | 106.7 / 108.8 ms | 108 | 426 MiB |
| Control | 50 | 5.972 s [5.905–6.040] | 3.159 s | 129.6 / 131.7 ms | 171 | 416 MiB |
| Candidate | 50 | 0.282 s [0.250–0.297] | 0.245 s | 119.0 / 126.1 ms | 117 | 436 MiB |

- **B1 passed.** At K=50 the candidate's slowest joiner finished in 0.282 s
  against 5.972 s, about 21× lower, and the worst candidate round (0.297 s)
  beat the best control round (5.905 s).
- **B2 passed.** At K=1 the candidate's median, 0.164 s, is below the 0.231 s
  limit.
- **B3 passed** at both K.
- **B4 passed.** 504 readiness samples across 36 rounds, with no failure.

The control's harness logs show the serialization directly: its 50 joiners
complete in a staircase about 0.12 s apart, so the median joiner waits about
half as long as the last. The candidate's K=50 to K=1 median ratio is 1.72;
the control's is 32.71.

**Verdict: PASS** on all four bars.

## Not yet measured

The plan also calls for K = 200 and K = 692 on this cell (692 is the harness
maximum: 700 members less the eight churners), comparing the same control
`1d0e4e155` against the merged main `8e1430e49`. Those points are prepared but
have not been run, and this receipt makes no claim about them.

## Limitations

- **One host, one shape.** These are same-host A/B results for one
  homogeneous IPv4 route-server fleet with 400,400 prefixes and a converged,
  GR-retained table. They are not a scale bound, a cross-daemon comparison, or
  a result for mixed wire profiles, Add-Path members or other address families.
- **Not a forwarding claim.** The clocks end when the harness has decoded the
  full table; nothing here measures forwarding or FIB state.
- **Joins only.** Concurrent ROUTE-REFRESH requests are still served one at a
  time; this receipt does not measure refresh coalescing.
- **Readiness fix in both arms.** The control includes #3038, which keeps
  `/readyz` served during full-table ROUTE-REFRESH replays. Measured
  separately, it adds about 9% to each 400,400-prefix refresh replay. It is
  present in both arms, so it does not bias this comparison, but absolute
  timings are not comparable with receipts taken on older mains.
- **Earlier invalid run.** The same job first ran on a control without #3038.
  Three K=1 cells, in both arms, failed the readiness bar while observer refresh
  replays were being served, so that run was invalid and contributes nothing
  here. After the fix landed, the whole job was re-run rather than only the
  failed cells.
