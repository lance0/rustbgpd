# EVPN terminal-debt qualification

This separate harness tests EVPN terminal-marker (EoR) debt after an ordinary
EVPN refresh feed has actually entered the outbound channel. It uses three real
TCP peers and observes the complete producer called by incremental distribution.
Production EVPN group ownership remains disabled. This receipt cannot authorize
activation, replace a soak, or qualify RTC or enhanced route refresh.

Its input is one explicit clean commit, named with `--base`: the product tree
together with the [qualification harness](../evpn-qualification/README.md) and
its driver. This harness adds only its own directory, checks that the input
carries the same qualification harness as its own head, and derives both arms
from that input.

## Cell types

Each campaign runs three required cell types with the same alternation, no-retry
and INVALID rules: five private/candidate pairs of timed overlap cells, then three
pairs of pressure cells, then three pairs of forced-refusal cells. A
correctness-only campaign runs one pair of each. Both timing and pressure
qualification must pass. Feed and receipt rows carry the daemon's wall clock and,
from the derived `main`, the same `CLOCK_MONOTONIC` the controller stamps on its
dispatches (`mono_us`, microseconds).

- **Timed overlap** cells dispatch the churn at refresh dispatch + 20 ms on the
  controller's `CLOCK_MONOTONIC`, sleeping then spinning; nothing observed from the
  daemon gates it, and no pressure witness is taken or required. The realised phase
  must lie in [20, 22] ms, and at least one client's refresh replay (a
  `data_admitted` row of 20,000 rows) must complete after the dispatch, in either
  arm; otherwise the cell is INVALID. Churn-applied is the dispatch to the last
  client's generation-2 actor input receipt, both on `CLOCK_MONOTONIC`, so source
  write and queueing behind the replays are inside it. Candidate medians must be at
  most private × 1.03, separately for churn-applied and resume-to-wire convergence.
  The phase, replays completed before dispatch and the replay residue are recorded
  per cell as diagnostics.
- **Pressure** cells keep the original no-refusal workload: churn waits for a live
  Pending write plus a kernel sample, and the same write's kernel limiting must
  span applied churn. Missing pressure evidence is INVALID. Their timings are
  diagnostic only and never enter the medians. This shows correctness under
  witnessed pressure, not a ≤1.03× result under it.
- In both no-refusal cell types the candidate's refresh tail must send each
  non-source debtor's markers at once: a `refresh_sent` row after the refresh
  dispatch and zero `refresh_refused`. Its EoR therefore precedes the churn on the
  wire. Every root called for the churn must report its work counters and visit
  zero repeated inventory rows; a root with no debtor owing markers owes no
  renewal.
- **Forced refusal** keeps the queue sizes, timer and actor state. After the
  readers pause, source zero announces real single-route UPDATEs from its unused
  pool indices (Type 2 `8000..15999`, then Type 5 `2000..3999`; at most 10,000).
  Each step sends at most the lowest observed debtor capacity minus one, only after
  every earlier route is admitted to both debtors, so it cannot overfill. The fill
  stops when a debtor's outbound channel has one free slot and its writer holds
  an unfinished Pending write; failing that within 60 seconds is INVALID. The
  ordinary refresh's data then takes the last slot (an admitted refresh row with
  `capacity == 0`). The candidate must record a `refresh_refused` row for that
  debtor whose complete, current feed owes markers, with the `refresh` refusal
  counter at least one; its absence is INVALID. After the readers resume, the controller waits for both the candidate retry
  send and a post-resume empty-channel sample before source zero withdraws the
  fill. The private arm waits for the same empty-channel sample. A source
  barrier proves the withdrawal applied, so the final inventory is unchanged.
  - Drain clock: the first debtor `sample` row at or after the resume dispatch,
    and no later than the withdrawal dispatch, whose channel is empty
    (`capacity == max_capacity`). Its absence is INVALID.
  - Retry proof: a read-only `retry_offer` event identifies the first eligible
    resync attempt with marker debt and channel capacity. The very next event
    for that peer must be `retry_sent`, with debt cleared, one added retry
    attempt and no added refusal. A skipped offer FAILs even if a later attempt
    is fast. An adjacent successful retry also proves capacity if the receiver
    freed a slot after a zero-capacity offer snapshot.
    Retry and drain clocks remain diagnostic; either can occur first. The retry
    may precede resume, but must follow the witnessed refusal.
    The controller waits for both under the existing 60-second bound. This
    prospective causal bar replaces the former one-second-plus-drain inequality;
    earlier receipts retain their original result and rule.
  - The private arm runs the same fill and must also show the refresh taking the
    last slot; it carries no debt and has no timing comparison.
  - Every root from the refresh dispatch to settlement, including the fill
    withdrawal, must report its counters and visit zero repeated inventory rows.

In both cell types every receiver's raw EVPN EoR must follow every route its
refresh covers (FAIL otherwise). In a forced-refusal cell the refresh also covers
the admitted fill: each filled route must reach every other peer twice, its first
announcement and its replay, before that EoR. ERR is not negotiated, so no EoRR
is on this wire.
Preparation archives that input and this harness separately, records both source
commits and archive hashes, and derives two independent source exports. Verification
compares every export input with both archives and the reviewed derivations.
Controller, process ownership, cleanup, cgroup, build conventions and the strict
Type 2/5 wire checker come from the explicit input. Its recovery sequence is not used.
Run and final analysis both verify binary hashes, distinct arms, successful
separate build exits and the frozen toolchain/source lineage. Each cell binds its
daemon PID/start time and binary hash to that arm; repeated processes or global
clock intervals cannot supply additional samples.

Run the checker tests before trusting a receipt:

```sh
python3 -B -m unittest discover -s bench/scale/evpn-terminal-debt -v
QUALIFICATION_SOURCE="$QUALIFICATION_SOURCE" python3 -B -m unittest discover -s bench/scale/evpn-terminal-debt -v
ruff check bench/scale/evpn-terminal-debt
shellcheck -x bench/scale/evpn-terminal-debt/run.sh
```

After committing the harness, prepare a new campaign directory. Supply the
qualification checkout explicitly; no current branch or implicit fallback is used.
For measured cells, also supply the predeclared UTC window with `--window-start`
and `--window-end`. Preparation refuses a dirty or different source.

```sh
python3 -B bench/scale/evpn-terminal-debt/terminal.py prepare "$CAMPAIGN" \
  --qualification-source "$QUALIFICATION_SOURCE" \
  --base "$(git -C "$QUALIFICATION_SOURCE" rev-parse HEAD)" \
  --daemon-cpus 24-27,56-59 --harness-cpus 28-31,60-63
taskset -c 0-23,32-55 python3 -B bench/scale/evpn-terminal-debt/terminal.py build "$CAMPAIGN"
python3 "$CAMPAIGN/sources/candidate/bench/scale/evpn-terminal-debt/terminal.py" verify "$CAMPAIGN" --built
bench/scale/evpn-terminal-debt/run.sh "$CAMPAIGN" --correctness-only
```

`--base` names the input commit: the product tree plus the qualification harness
and driver, which must match this head's copies. A campaign may name any input
with the same harness, which is how two product trees are compared (below).

Coordinate build capacity first: the build command runs one Cargo process at a
time, pinned to CPUs 0–23,32–55 with eight jobs. Candidate and private daemons use
separate targets and must have different binary hashes. Both private exports use
the same instrumentation and real socket settings. No actor state, queue size,
timer, or selection-deferral state is synthesized or changed.

The fixed workload and bars are also recorded on the working ticket before any
dispatch. Forced-refusal cells replace the churn with the fill described above:

- Three peers, each with 8,000 Type 2 and 2,000 Type 5 routes; two stable export
  policy groups; ordinary refresh, without negotiating ERR.
- Initial load and source-applied EoR barrier, then a capture boundary, then actual
  confirmed initial receiver EoRs, then actual socket-reader pause before refresh.
  Source zero sends one mixed UPDATE replacing
  one route of each type, followed by a source EoR barrier. The two withdrawals
  name index zero, and the two announcements name the next unused indices
  (8,000 for Type 2 and 2,000 for Type 5): four distinct NLRI identities, four
  operations, and exactly one churn round.
- Requested TCP send and receive buffers 4,096 bytes, Linux readback 8,192 bytes;
  actual `TCP_NOTSENT_LOWAT` 4,096. Both outbound queues remain 4,096 entries and the
  marker retry timer remains one second. The daemon alone has a 12 GiB cgroup and
  zero swap. Provenance budgets stay 16 MiB per peer and 256 MiB per daemon, with
  every raw observation at or below 80% and all five reset causes zero.
- Runs before the marker fix (2026-10-27, 2026-11-02) also required admitted
  debt spanning the churn; the fixed build sends the markers at once, so
  no-refusal cells no longer check it. That witness was: a real nonempty data
  admission must produce a complete, current completion with positive owed markers, current session identity and matching channel. An actual
  incremental root call must retain that state before work and admit the changed
  keys with a changed completion target table stamp. The completion revision is a
  provenance fence and can be reused; it is not a route revision counter.
  The same session and channel must still owe
  a marker after the actor applies the source barrier. Later revisions are allowed
  only with a recorded real data admission or a proved complete no-op from the
  actual producer; an unexplained revision change fails. Raw receiver route state
  independently proves the changed keys. A socket-write acknowledgement alone
  proves none of this.
  A stable observer token uses weak channel identity: reconnect can reuse a session
  actor ID, so matching the current channel at each point is insufficient. The
  observer retains no strong sender and rejects a changed channel token.
  The root's before-state is captured before staging changes its group table
  stamp. The producer's internal stamp replacement is observed through its new
  complete admission; it is not mistaken for an externally stale session/feed.
- Kernel evidence requires a first-Pending write event and an increase in the
  kernel's cumulative `rwnd_limited` or `sndbuf_limited` duration. Both `ss` samples
  must be wholly inside that unfinished write, matched by the live socket cookie. The same write must already be
  Pending at the actual root's before-state and remain unfinished through actor
  application. The sample-pair interval must overlap that root-to-application
  interval; earlier pressure alone cannot qualify later churn. `notsent`, Pending, and a reader
  pause alone are insufficient. The 20 Hz sampler retains its original `ss` output.
- Count staging and member delta visits, every complete-producer attempt, both
  projection-completeness walks, the current inventory walk, the OLD inventory
  and delta walk, and successful proof projection. Include actual data rows,
  data admissions and terminal admissions from the actual distribution root.
  A current feed renewed from its member delta payload counts its sparse seal and
  staged-key verification instead; a root with neither renewal path is INVALID.
  After a complete current feed is admitted, the repeated full-inventory visit
  bar is **zero**; source evidence is not a substitute for the retained live receipt.
- Readiness runs at 20 Hz through all workload phases: all HTTP 200, every request
  below 200 ms, no missing probe and no scheduling lag of 50 ms or more. The series
  is bound to the controller's monotonic clock: the first probe is scheduled at most
  one 50 ms interval after load dispatch, the last at most one interval before
  finish completion, and every probe lies inside the cell. A shifted or truncated
  series is INVALID. Every
  convergence is at most 60 seconds. The debt witness wait is bounded at two
  seconds; this changes no daemon timer and cannot extend an expired debt window.
- Verify every receiver's actual framed socket UPDATE bytes against the checked
  capture, all route identities and attributes, strict withdrawals, full refresh
  coverage before EoR, terminal ordering, final route set and complete settlement.
  Raw BGP type 5 is rejected because this leg does not negotiate ERR. An ERR leg
  would require capability, capture, BoRR/EoRR parser and ordering extensions.
- Measured order is private/candidate, five timed overlap pairs, then three
  pressure and three forced-refusal pairs. Only timed overlap cells carry medians.
  Private bar misses remain baseline evidence; technical invalidity or a candidate
  miss stops later cells. No medians qualify an incomplete matrix. Correctness cells
  publish no comparative performance measurements.

The raw consumer runs online and again during `analyze`. `FAIL` means an observed
bar miss or absent required witness; malformed or inconsistent evidence is
`INVALID`. Failed directories are retained and cannot be reused. Marker refusals
come from per-peer attempt/refusal counters at every standalone terminal-marker
`try_send` site: the deferred-EoR flush, the initial-table EoR,
and the shared `try_send_evpn_feed_markers`, attributed by its caller: `retry`
for the one-second resync tick and `refresh` for the PeerRefresh tail. A marker
carried in a data batch shares that batch's channel reservation, so its refusal
is a data refusal. A missing site counter is INVALID, never zero. Claim that
backpressure prevented marker admission only from a forced-refusal cell's
observed `refresh` refusal.
Analysis continues checking later raw cells after a private acceptance miss;
technical corruption overrides `FAIL` with `INVALID`. A partial private failure
is retained as unvalidated evidence and never supplies comparative medians.

To analyze an existing campaign without launching a daemon:

```sh
python3 -B "$CAMPAIGN/sources/candidate/bench/scale/evpn-terminal-debt/terminal.py" analyze "$CAMPAIGN"
```

The [2026-10-27 correctness receipt](results/2026-10-27.json), measured on source
`7fab2c4` with the explicit `a5da4df` input, is **FAIL**. The private arm passed.
The candidate established genuine admitted debt spanning applied churn under
kernel backpressure and passed receiver wire, settlement, readiness, headroom and
reset checks, but visited 899,970 inventory rows across four actual root calls
against the predeclared zero-work bar. No N=3 timing campaign followed the miss,
and production ownership remains disabled.

On 2026-11-01 the receipt's affected claims were requalified against the retained
raw records; no cell was rerun. The work-count FAIL is unchanged. The new readiness
binding passes on both cells: each first probe is scheduled about 3 ms before
load dispatch, each last probe 14–19 ms before finish completion, and every gap
is 50 ms. Marker-refusal accounting is INVALID for this run. It recorded no
flush-path refusal event, but the retry and initial-table send sites were not
instrumented. The run therefore establishes
admitted debt under kernel backpressure. It does not establish whether that debt
was timer-deferred or refused at marker admission.

## Parent-versus-candidate comparison

`compare.py` measures the cost of a product change on the timed overlap cell. It
freezes two ordinary campaigns side by side, one per product tree, each on its
own input commit, and runs only their owned arm:

```sh
python3 -B bench/scale/evpn-terminal-debt/compare.py prepare "$COMPARISON" \
  --parent-input "$PARENT_INPUT" --candidate-input "$CANDIDATE_INPUT" \
  --window-start "$START" --window-end "$END"
taskset -c 0-23,32-55 python3 -B "$COMPARISON/parent/sources/candidate/bench/scale/evpn-terminal-debt/compare.py" build "$COMPARISON"
python3 -B "$COMPARISON/parent/sources/candidate/bench/scale/evpn-terminal-debt/compare.py" plan "$COMPARISON"
bench/scale/evpn-terminal-debt/run.sh --compare "$COMPARISON"
```

Each input is the product commit with this branch's qualification harness and
driver. `prepare` and every later step refuse two inputs whose `src/` and
`crates/` trees are the same; binary digests are not compared, because each
daemon embeds its own build directory. `run.sh --compare` takes the canonical
host lock and holds it for the whole comparison; the runner refuses to start
unless its inherited descriptor is that lock file and the lock is held. It
executes 30 timed overlap cells: ten A/A cells on the parent
binary, ten ABBA cells, ten confirmation cells; every timed cell passes the UTC
window check and the quiet-host gate. A field (churn-applied, convergence) fails
only when its ABBA ratio and its confirmation ratio both exceed
max(1.02, its A/A ratio + 0.01). The first cell that is not PASS ends the
comparison; nothing is retried. As in every measured campaign of these harnesses,
the quiet-host gate samples the host only before each cell: a compiler that
starts during a cell is waited out by the next gate and does not invalidate the
cell it ran beside, so the window must stay hands-off. There are no report-only cells: no shape of this
harness isolates a clean-delta owned pass or a refused-member pass.
