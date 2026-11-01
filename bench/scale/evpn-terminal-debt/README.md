# EVPN terminal-debt qualification

This separate harness tests timer-deferred terminal-marker debt after an ordinary
EVPN refresh feed has actually entered the outbound channel. It uses three real
TCP peers and observes the complete producer called by incremental distribution.
Production EVPN group ownership remains disabled. This receipt cannot authorize
activation, replace a soak, or qualify RTC or enhanced route refresh.

The harness is independent of the qualification branch. Its required input is
the clean qualification commit `a5da4df26898b3658511babd3cb919e130b7fc40`
from [the qualification PR](https://github.com/lance0/rustbgpd/pull/3440).
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
  --base 110dd43f9be38901fc7826eb74673b7c6d2bc0d6 \
  --daemon-cpus 24-27,56-59 --harness-cpus 28-31,60-63
taskset -c 24-31,56-63 python3 -B bench/scale/evpn-terminal-debt/terminal.py build "$CAMPAIGN"
python3 "$CAMPAIGN/sources/candidate/bench/scale/evpn-terminal-debt/terminal.py" verify "$CAMPAIGN" --built
bench/scale/evpn-terminal-debt/run.sh "$CAMPAIGN" --correctness-only
```

Coordinate build capacity first: the build command runs one Cargo process at a
time, pinned to CPUs 24–31,56–63 with eight jobs. Candidate and private daemons use
separate targets and must have different binary hashes. Both private exports use
the same instrumentation and real socket settings. No actor state, queue size,
timer, or selection-deferral state is synthesized or changed.

The fixed workload and bars are also recorded on the working ticket before any
dispatch:

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
- A real nonempty data admission must produce a complete, current completion with
  positive owed markers, current session identity and matching channel. An actual
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
  must be wholly inside that unfinished write and the continuous positive-debt
  interval, matched by the live socket cookie. The same write must already be
  Pending at the actual root's before-state and remain unfinished through actor
  application. The sample-pair interval must overlap that root-to-application
  interval; earlier pressure alone cannot qualify later churn. `notsent`, Pending, and a reader
  pause alone are insufficient. The 20 Hz sampler retains its original `ss` output.
- Count staging and member delta visits, every complete-producer attempt, both
  projection-completeness walks, the current inventory walk, the OLD inventory
  and delta walk, and successful proof projection. Include actual data rows,
  data admissions and terminal admissions from the actual distribution root.
  After a complete current feed is admitted, the repeated full-inventory visit
  bar is **zero**. The pinned implementation is expected to breach this bar;
  source evidence is not a substitute for the retained live receipt.
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
- Measured order is private/candidate, three pairs. Candidate medians for
  controller dispatch of the source-UPDATE command through actor application
  (including actual source write/drain), and resume-to-wire-convergence must each be at
  most private × 1.03. Private bar misses remain baseline evidence; technical
  invalidity or a candidate miss stops later cells. No medians qualify an incomplete
  matrix. Correctness cells publish no comparative performance measurements.

The raw consumer runs online and again during `analyze`. `FAIL` means an observed
bar miss or absent required witness; malformed or inconsistent evidence is
`INVALID`. Failed directories are retained and cannot be reused. If the natural
timer window closes during churn, the fixture fails without changing its timer,
buffers, workload or bars. Marker refusals come from per-peer attempt/refusal
counters at every standalone terminal-marker `try_send` site: the deferred-EoR
flush, the one-second marker retry and the initial-table EoR. A marker carried in
a data batch shares that batch's channel reservation, so its refusal is a data
refusal. A missing site counter is INVALID, never zero. A zero
marker-admission-refusal count is allowed: call the result **timer-deferred
terminal debt under kernel backpressure**. Claim that
backpressure prevented marker admission only if a real refusal was observed.
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
