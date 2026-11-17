# rrtransport

Deliberate CI-run correctness tripwire: the `smoke` shape executes on every PR; the gated scale instrument below is operator-initiated.

`rrtransport smoke` is a fixed-shape correctness harness for the real
route-reflector transport path. It starts a production `RibManager`, two
production transport sessions over TCP loopback, and the existing
`rustbgpd-evpn-load` peer handshake/decoder. Four synthetic ingress sources
inject exactly 100 unique IPv4 `/24` routes through `RibUpdate::RoutesReceived`.
Each target listener remains bound while its actual ephemeral address is given
to rustbgpd, then that exact socket is transferred into the peer handshake.

The smoke preloads the RIB before registering either target session, then
asserts one shared update group, exact staged Adj-RIB-Out counts, and exact
wire-side initial-dump prefix sets through each IPv4 End-of-RIB. It prints one
stable JSON receipt and a human summary. It is deliberately not a benchmark:
the shape is fixed and it makes no latency, throughput, RSS, or competitor
claim.

Run from the repository root:

```text
cargo run --locked -p rrtransport -- smoke
```

## Fixed scale instrument

`rrtransport rr1000 <output-dir>` is the measurement-only real-transport
instrument. Its shape is intentionally not configurable: 1,000 uniform
IPv4-unicast iBGP route-reflector clients, 100,000 distinct `/24` routes from
four sources, and a 12-worker Tokio runtime. Every listener is retained through
accept. All sessions establish against an empty RIB and drain exactly one empty
initial EoR before T0. The receipt reports injection-finished, exact staged
Adj-RIB-Out convergence, and exact decoded wire convergence separately.

Wire classification retains one expected table and a 100,000-bit bitmap per
client. It rejects missing or outside prefixes, duplicates, withdrawals,
decode failures, incomplete sessions, and more than one update group. It counts
decoded NLRI, not UPDATE messages. One aggregate 120-second deadline covers
setup, convergence, validation, and shutdown.

Wire completion is explicitly `first_exact_bitmap`: a peer completes when its
bitmap first covers the fixed expected prefix set with exact decoded-NLRI
cardinality. Duplicate, withdrawal, outside-set, decode-failure, and message
counters describe input observed through that boundary only. The instrument
does not claim a trailing quiet period, writer flush, refresh pass, teardown
marker, or absence of later UPDATEs.

Run the three-attempt campaign only through:

```text
bench/scale/rrtransport/run-receipt.sh /absolute/output/outside/the/repository
```

The runner requires 4,096 file descriptors, 16 GiB available RAM, performance
CPU governors, a quiet host, no competing BGP daemon, and a clean source tree.
It owns a host lock, enforces a 2 GiB whole-process RSS ceiling, a 300-second
per-run guard, and a 20-minute campaign guard.

Before starting the supervised target, the runner executes an explicitly
untimed grouped-commit correctness leg through the production RIB seam and
transport-session encoder. Its schema-2 receipt separates the one-dispatch
65000:100 seed from a fast wire-visible RPOL transition to 65000:200. The
transition records its native shared plan, exact probes, route-shell
materialization, and zero authoritative per-peer fallback. Concrete transport
snapshots plus common group-token and announce-vector identities prove the
shared envelope path. The full-shape leg runs once and its result is
copied into each attempt.

Each measured target records direct-PID `VmRSS`/`VmHWM` and jemalloc allocated,
active, resident, and mapped bytes at established, staged, and wire
checkpoints. The runner's process-tree target sampler remains separately named
and reported. Receipts also retain per-peer evidence, logs, the exact source
commit, workload and host conditions. A `COMPLETED` file containing `pass` is
written only after all three attempts pass the semantic verifier. Results are
not comparable to the historical unavailable scratch harness and must not be
published as an A/B.

Raw `VmHWM` checkpoints retain Linux's asynchronous `/proc` observations. The
verifier always requires `VmHWM >= VmRSS`, permits at most a 4 MiB apparent
high-water regression between checkpoints, and rejects any larger dip. The
tolerance is 0.2% of the harness's 2 GiB RSS ceiling and matches the existing
persisted-config receipt convention.

A three-attempt full campaign on 2026-08-29 ran at repository commit
`05a71687ff3f4787eb1eb90a180fa7bd817e36c5`. Its three staged-convergence
times were 295, 300, and 307 ms; exact wire-convergence times were 330, 334,
and 329 ms. The full-shape verifier therefore rejects staged time above 354 ms
or wire time above 385 ms, 15% over the respective observed maxima. The tiny
CI correctness fixture does not apply these performance ceilings.

CI never runs the scale shape. It runs the original smoke, a 4×100 real-TCP
fixture through the same scale collector/verifier/RSS seams, and destructive
parser/mechanics fixtures.

## Outbound-credit cells

`rrtransport credit-*` runs the cells that qualify a change to the RIB's
per-peer outbound credit. A production `RibManager` drives production
transport sessions over TCP loopback to the same synthetic receivers as the
smoke; sources inject through `RibUpdate`. The harness never sets the credit:
each cell runs at the default credit of the tree the binary was built from,
and it reads only metrics that exist on every tree it compares. It records
`bgp_rib_outbound_credit_bytes` when the tree exports it and never needs it
to run. Every wire reference comes from the harness's own injection log,
never from the daemon's Adj-RIB-Out.

| Cell | Mode | Shape | What it records |
| --- | --- | --- | --- |
| 1 | `credit-paused` | 150 private EVPN receivers, all socket reads paused; one source re-announces 37,500 routes every 2 s with alternating `LOCAL_PREF` for 240 s | cgroup `memory.peak`, VmRSS/VmHWM, jemalloc allocated, credit-rows and (when present) credit-bytes peaks |
| 2 | `credit-exhaust unicast\|evpn` | ordinary announce burst: 150 private receivers, already past their End-of-RIB, paused for 80 s while an established source sends 150,000 fresh routes, one 1,024-route UPDATE every 500 ms | exhaustion witness, exact final wire state, End-of-RIB order, session resets, recovery time |
| 3 | same run as cell 2 | one more receiver that gets none of the burst, only a separate source's single route replaced every 20 ms | max delivery gap and latency quantiles at that receiver |
| 7 | `credit-restart unicast\|evpn` | the cell 2 fixture behind an RFC 4724 restart: selection deferred, 150 private receivers paused for 30 s while the restarting source sends 150,000 routes at once and its End-of-RIB | exact final wire state, End-of-RIB order, session resets, recovery time, the same unaffected receiver, longest actor poll, turn and owed-drain step, live-operation and credit gauges; no witness |
| 7 | `credit-restart-churn unicast\|evpn` | the same release, with every 100th burst route withdrawn and every other one of those re-announced at a new MED while the release drains | the cell 7 record, against the post-churn reference, and when the churn was sent |
| 4 | `credit-probe` | in-process healthy-lag cells (unicast and EVPN, 150 and 1,000 peers, 0.5 s and 2 s stalls) and the 150-peer restart-during-dump probe, whose receivers join through the production `PeerUp` path and keep their 150,000-row initial tables queued while the 50,000-row tail arrives | dirty episodes and queued rows per receiver |
| 6 | `credit-fill unicast\|evpn\|vpn\|flowspec` | 150 paused private receivers (unicast and VPN through the same peer-context policy); one source sends 150,000 fresh routes of the family; FlowSpec rules carry a prefix, 16 ports and 8 length ranges | bytes per queued row (report-only) |

Cell 5 (Criterion) is not part of this harness.

**Cell 2.** The burst routes carry distinct attributes (one UPDATE a route,
about 180 bytes on the wire) and the receivers' sockets have a 16 KiB receive
buffer, so a paused receiver's kernel buffers and writer budget absorb only a
small part of the burst; the rest stays queued against the credit. The source
is established and not restarting, so every burst route reaches each receiver
through an ordinary pass: the path that charges the receiver's credit and,
once the credit is spent, records the keys the receiver is owed. Checks, per
burst receiver: the final decoded table equals the injected one (every route
present at its MED, nothing withdrawn, no route outside the burst keys, no
undecodable UPDATE; an EVPN route counts only with the burst's RD and
originator), exactly one End-of-RIB arrives and it precedes every burst route
(the receiver's initial one; the harness waits for it before pausing), and
the session never ends (stub stream open, no NOTIFICATION, transport still
Established; the healthy receiver's session counts too). Recovery runs from
the first burst UPDATE to the moment every burst receiver is exact, on the
harness clock; it includes the paced burst (73.5 s) and the rest of the fixed
80 s pause. `drain_after_resume_ms` reports the part after the readers
resume. If burst submission ran past the pause deadline, the readers would
stay paused until it ended, so the result records `actual_pause_ms` (from
the moment every burst reader acknowledged its pause to every reader's
acknowledged resume). The run is INVALID when the burst's last UPDATE
(`release_sent_ms`) is not before `shape.pause_ms`, or when `actual_pause_ms`
is more than 250 ms from `shape.pause_ms`; the analyzer also refuses to
compare arms whose runs' actual pauses spread more than 250 ms.

Because `recovery_ms` includes the fixed pause, a bar on it is insensitive
to the drain: on the untimed full shape the parent recovers in about 90.5 s,
10.5 s of it after the resume, so the old rule max(90.5 × 1.25, 90.5 + 2) =
113.1 s let a candidate drain for 33.1 s. The cell 2 bar is therefore
absolute and on the drain: in every candidate run, `drain_after_resume_ms`
(from every reader's acknowledged resume to the last burst receiver's exact
table) is at most 60,000 ms. The old recovery rule and the same rule on the
drain stay as labeled report-only lines (medians, ratios and the time each
rule would allow); they never change the verdict.

The burst is paced because the RIB is serial: sent at once, 150,000 routes
toward 150 private receivers occupy it for tens of seconds on any tree, with
the readers paused or not, and the healthy receiver's churn waits behind them
in the RIB's queue. That delay measures the backlog, not the credit. One
1,024-route UPDATE every 500 ms is about half the rate the RIB stages them,
so the queue stays short and cell 3 shows what spent credit costs a healthy
peer. A receiver stub's read deadline runs from its last read and keeps
running across a read pause, and the daemon's KEEPALIVEs put that read up
to the 90 s negotiated hold time before the pause. The stubs therefore time
their reads out after a local 240 s (the negotiated hold time stays 90 s),
and the harness refuses to start a pause that, with 90 s since the last
read, would reach it.

**Exhaustion witness.** The cell must show that every burst receiver spent
its ordinary credit. The witness reads the credit gauge, summed over peers:
`bgp_rib_outbound_credit_bytes` on a tree that exports it, else
`bgp_rib_outbound_credit_rows`. The expected value is the number of burst
receivers times the tree's per-peer credit at the cell's 153 registered peers
(the burst receivers, the healthy one and the two sources): 2 GiB / 153 =
14,035,840 bytes on a byte-credit tree, 16,777,216 / 153 = 109,655 rows on a
row-credit tree. Every burst row charges the same amount (a row on a
row-credit tree; `row_size_of` + 146 bytes on a byte-credit one) and
admission stops a peer below its credit plus one row, so a peer holds at most
ceil(credit / row) rows and exactly that many once it reached its credit:
150 × 56,144 × 250 = 2,105,400,000 bytes for unicast and 150 × 48,400 × 290 =
2,105,400,000 for EVPN on a byte-credit tree, 150 × 109,655 = 16,448,250 rows
on a row-credit tree. A window instead of the exact value would let the
others' sub-row overshoot hide a short receiver: 149 receivers at 56,144
unicast rows and one at 56,048 sum to 150 × 14,035,840 bytes.

A single peak cannot carry that check, because the healthy receiver's churn
row is in the sum too: 149 receivers at 109,655 rows, one at 109,654 and one
healthy row total exactly 16,448,250, and a 250-byte burst row and a
250-byte healthy row trade the same way on a byte-credit tree. The witness
therefore reads the plateau. While the readers are paused, the burst
receivers' charge is constant from the moment the last of them reaches its
credit until the resume; the healthy receiver's row comes and goes. Nothing
bounds how often a sample catches it: the RIB publishes both gauges once at
the top of each of its turns, so a turn that staged a churn row publishes
it unless the healthy receiver's transport wrote it first, and the value
then holds until the RIB's next turn. With churn every 20 ms, nearly every
turn during the plateau is a churn turn. On a 4-receiver run with a 10 s
pause the row was in none of 40 samples, but how often it is under the full
shape's RIB load is not measured, and a plateau could carry it in every
sample.

So the harness makes the healthy row separable. A churn-free window ends
the pause: 300 ms before the resume, it stops the churn task (joined, so
nothing more is sent), waits until the healthy receiver has the last churn
row, waits 20 ms for that envelope's credit to return, and sends the RIB two
`QueryLocRibCount` queries; the RIB serves the second only in a turn that
began by publishing the gauges, so the next readings carry no churn row. It
then reads the gauge every 10 ms until the pause deadline, restarts the
churn with the next sequence number and resumes the readers. The result's
`witness.plateau` records the sampler's 250 ms sleep between samples, the
churn-free window (`quiet`: when the churn stopped, when its last row
arrived, when the gauges were republished, the readings' count, minimum and
maximum) and the plateau: the sampler's samples from the first at or above
the churn-free minimum to the last one taken before the resume was issued
(`resume_issued_ms`), with their bounds, count and how many sat above that
minimum, and the minimum and maximum over those samples and the churn-free
readings together. The analyzer accepts the plateau only when its minimum
is exactly the expected value, the churn-free minimum equals that minimum,
its maximum is at most one healthy row (`healthy_row_size_of` + 146 bytes,
or one row) above it, the churn-free window holds at least one reading
after the last churn row arrived and lies inside the plateau, and the
plateau holds at least 40 samples. A short receiver plus a healthy row then
shows a churn-free minimum one row short of the expected value. Every other
plateau is INVALID, never PASS, and the verdict line names the numbers.

40 samples is 10 s at 250 ms. The fixed shape reaches the row-credit tree's
credit at the 108th UPDATE, about 53.5 s into the pause, and a byte-credit
tree's earlier, so a run that exhausts as designed leaves at least 26 s,
about 100 samples, before the 80 s resume. Fewer than 40 means credit was
reached only in the burst's last seconds or the sampler stalled. The window
is a deliberate gap of about 0.3 s in the healthy receiver's delivery, so
the gap calculation leaves it out: from when the churn task had stopped
(`quiet.churn_stopped_ms`) to when the churn restarted, recorded as
`unaffected.quiet_excluded` (`from_ms`, `to_ms`, `span_ms`). A gap counts
only its part outside that span, so the last row's delivery before the
window and the first row's after it still count. `unaffected.max_gap_ms` is
the gap after the exclusion, `max_gap_raw_ms` the gap without it; the
analyzer reports both and the excluded span. The restart cells hold the same
window and exclude it the same way.

The guarantee rests on two things the harness cannot see per peer, since
the credit gauges are unlabeled and only their sum is readable. Admission
must stop each burst receiver at the same ceil(credit / row) rows: a tree
that admitted more to one peer (a multi-row envelope admitted just below
the credit) could hide another one short by that excess. And the plateau
must contain a reading without the healthy row: the churn-free window is
the harness's means to that, and its evidence is the recorded arrival of
the last churn row before the gauges were republished.

Credit refusals (`bgp_outbound_commit_refusals_total{reason="outbound_credit"}`)
are recorded and reported but are not a witness: the same reason counts a
refusal made only because a whole-table operation is live, with no row
charged. A clean peer past its credit owes keys instead of refusing, so the
full shapes show none.

The analyzer also checks arm identity: the parent's exhaustion results must
lack `bgp_rib_outbound_credit_bytes` and the candidate's must carry it, so
two builds of one tree cannot pass as the pair (cells 2 and 3 INVALID
otherwise). `witness.receivers` must equal `shape.receivers`.

Owe-whole flips (`bgp_rib_outbound_owing_flips_total`) are recorded but are
not a witness. An RFC 4724 selection release owes its family whole to every
private receiver by design, one flip per receiver at any table size, and
delivers it as an uncharged whole-table operation: a 4-receiver, 4,096-route
restart burst shows 4 flips with no credit in use. That is why the restart
burst is no longer cell 2; it is cell 7 below. A result whose
`shape.trigger` is not `ordinary_announce_burst` is INVALID as cell 2.

The credit-rows, credit-bytes, dirty-peer and live-operation gauges are
sampled by the RIB once per run-loop iteration, so a RIB unit that spans a
whole cell would hide them; the paced burst gives the RIB an iteration per
UPDATE.

**Cell 7.** The RFC 4724 selection release and the drain of what it owes.
The restarting source re-establishes first, so the selection gate is armed
before any receiver registers; the 150 burst receivers pause their reads,
the source sends its 150,000 routes at once and its End-of-RIB, and the
release owes each private receiver its family whole. Readers resume after
30 s. Checks, per burst receiver: the final decoded table equals the
reference, exactly one End-of-RIB arrives, every route of the table
precedes it, and no session ends.

`credit-restart-churn` adds churn while the release drains. Halfway to the
churn-free window (14.85 s into the pause on the full shape), with the
release queued ahead of it and every burst reader still paused, the source
withdraws every 100th burst route (1,500) and then re-announces every other
one of those (750) at MED 9. The reference is the post-churn table:
withdrawn routes absent, re-announced ones at MED 9, the rest at MED 7. A
churned route may arrive on either side of the End-of-RIB (a withdrawal
behind the marker is an ordinary UPDATE); every other route must precede
it, and `wire.withdrawn_survivors` counts withdrawn routes a receiver still
holds at the end (also a `final_state_exact` failure). The churn counts only
when its timestamps put it inside the drain: `churn.started_ms` at or after
`timing.release_sent_ms` and `churn.sent_ms` before `timing.last_eor_ms`
(the last burst receiver's End-of-RIB, on the harness clock); otherwise the
run is INVALID, in `check` and in the analyzer.

**Turn, step and gauge instruments.** The harness runs the RIB in-process
and reads production metrics from its registry; it adds no product metric
and patches nothing. What each recorded number measures:

- `actor.slice_max_us`: the whole-run maximum, in microseconds, of
  `bgp_rib_actor_slice_max_microseconds` per stage. The RIB keeps that
  maximum since the previous render and resets it when a render publishes
  it, so a plain registry read sees 0. The harness publishes and reads it
  every 250 ms (`actor.reads`), once more at the cell end, and keeps the
  maximum of the readings; nothing else in the process renders. A slice is
  counted when its poll ends. `actor_poll` is one whole poll of the RIB
  task in wall-clock time, executor handoffs included, at microsecond
  resolution. A poll holds whole turns (a turn never yields) and often many:
  on the reduced shape the 48 message turns of setup fit in one or two
  polls. So the poll
  maximum bounds every turn, timer expiry and resync tick from above but
  can be several of them. The other stages cut polls at every 64th
  readiness checkpoint and are shorter than the work they sit in. The
  window runs from t0 (readers paused, before the burst) to the cell end;
  `actor.setup_slice_max_us` is everything before t0. A poll in progress at
  t0 counts in the run.
- `actor.turn_longest_ms` and `actor.work_longest_ms`: per `kind` of
  `bgp_rib_actor_turn_duration_seconds` (one message turn) and per
  `work_unit` of `bgp_rib_actor_work_duration_seconds` (route chunks and
  distribution windows, which run outside message turns), the number of
  observations in the run window and the bucket edges around the longest:
  above `above_ms`, at most `at_most_ms` (null past the 30 s top edge). The
  edges are 1, 5, 10, 25, 50, 100, 200, 500 ms, 1, 2.5, 5, 10 and 30 s: they
  can show a turn over 250 ms only from the 500 ms edge up, and no
  histogram covers resync ticks or other timer expiries.
- `actor.owed_drain_step_longest_ms`: the same bracket for
  `bgp_rib_outbound_owed_drain_step_seconds`, null on a tree without it.
  No tree exports it yet: nothing in the RIB times one owed-drain step.
  The drain's readiness checkpoints are unnamed, so its slices fall in
  stage `other` with every other unnamed checkpoint and are cut at every
  64th checkpoint, not at step boundaries. The smallest product metric that
  would isolate a step is that histogram, labeled `scope` = `whole` or
  `keyed`, with the stall buckets (exact edges at 50 and 250 ms), observed
  around `distribute_owing_drain` in `RibManager::owing_drain_step`
  (`crates/rib/src/manager/outbound_owing.rs`); the harness reads it as
  soon as a tree exports it under that name.
- `drain_gauges`: from the release (`from_ms`) to the cell end, the getter
  values of `bgp_rib_outbound_operations_live` and
  `bgp_rib_outbound_credit_rows`, read every 1 ms (`reads`): the peak of
  each, and the first and last reading with a live operation. The RIB
  publishes both once per run-loop iteration, so a value that lives inside
  one iteration is invisible. The live-operation gauge is unlabeled: it
  counts every family's whole-table operations, at most one per peer. In a
  unicast release cell every whole-table operation is unicast; in an EVPN
  one the peak is reported, not gated. On a tree with
  `bgp_rib_outbound_credit_bytes` the byte peak is the sampler's
  (`witness.peak_credit_bytes`, every 250 ms): the harness has no getter for
  it.

The cell-7 bars read the candidate's measured fixed-shape runs only:

- Bar 1, its own line over every release run: the longest owed-drain step
  at most 50 ms. PASS when every bracket's `at_most_ms` is at most 50, FAIL
  when an `above_ms` is at least 50, otherwise INVALID; INVALID "no
  instrument" while the field is null, as it is on every tree today.
- Bar 2: the longest RIB actor turn during the release and its drain, over
  the whole run window, at most 250 ms. PASS when `slice_max_us.actor_poll`
  is at most 250,000; FAIL when a turn or work unit's `above_ms` is at least
  250; otherwise INVALID, because a longer poll may hold many short turns.
- Bar 3: the healthy receiver's longest delivery gap, outside the
  churn-free window, at most 1 s.
- Bar 4: the wire checks above, and for the churn variant the churn inside
  the drain (INVALID otherwise).
- Bar 6: for unicast, `drain_gauges.peak_operations_live` is 0; and the
  summed credit gauge's peak is at most receivers × (per-peer credit + one
  1,024-row pass), in the unit of cell 2's witness (rows: 150 × (109,655 +
  1,024); bytes: 150 × (14,035,840 + 1,024 × (`row_size_of` + 146))).

A mixed-family release cell and a release by deferral-timer expiry are not
part of this harness.

**Cell 6.** Method: the least-squares slope of jemalloc allocated bytes over
`bgp_rib_outbound_credit_rows`, sampled every 50 ms with every reader paused,
using samples before the first credit refusal and between 10% and 90% of the
pre-refusal credit-rows peak. Each queued fresh row adds its envelope row and
its Adj-RIB-Out entry, the terms the candidate charges. Error terms: the
source's own Adj-RIB-In and Loc-RIB growth, shared by 150 receivers (about
1/150 of a row's source cost each); encoded frames in the writer budget (at
most about 0.6 MiB a receiver, filled first); and allocator noise, reported as
the slope's standard error. The analyzer compares the estimate with the
candidate's charge (row element plus 146 bytes) and flags a family more than
25% above it.

### Running

Build one binary per arm from its own tree (the candidate tree must contain
this harness), and check that the two differ:

```sh
CARGO_INCREMENTAL=0 cargo build --locked --profile scale -p rrtransport
sha256sum target/scale/rrtransport
```

Correctness first, a few minutes, no timing (reduced shape: 4 receivers,
4,096 rows; credit is not reached, so the witness reads INVALID by design):

```sh
bench/scale/rrtransport/run-credit-cells.sh --reduced PARENT_BIN /abs/out/parent-smoke
python3 bench/scale/rrtransport/credit_bars.py check /abs/out/parent-smoke
```

`--correctness-only` without `--reduced` runs the full shapes untimed, for
example to show that cell 2 exhausts credit on a tree. The default cell
list ends with the four release cells (`restart-<family>` and
`restart-churn-<family>`); name cells to run a subset. A `--pause-ms` or
`--seconds` override on the binary also marks its result correctness-only:
only the fixed shape is a measurement.

One arm's full set takes about 19 minutes of cells (about a minute for each
release cell) plus the quiet-host
gate before each (at least a minute each on a quiet host); an A/A, ABBA and
confirmation schedule is about two hours. The measured run holds the host lock, passes the quiet-host gate before each
cell, and runs each cell in its own systemd user scope with swap fenced (12
GiB for cell 1, 64 GiB otherwise). Lay repetitions out as subdirectories of
one directory per arm, for example in ABBA order:

```sh
bench/scale/rrtransport/run-credit-cells.sh PARENT_BIN /abs/out/parent/1
bench/scale/rrtransport/run-credit-cells.sh CANDIDATE_BIN /abs/out/candidate/1
bench/scale/rrtransport/run-credit-cells.sh CANDIDATE_BIN /abs/out/candidate/2
bench/scale/rrtransport/run-credit-cells.sh PARENT_BIN /abs/out/parent/2
python3 bench/scale/rrtransport/credit_bars.py analyze /abs/out/parent /abs/out/candidate
```

The analyzer prints one `PASS`, `FAIL` or `INVALID` line per cell and never
stops at the first failure. Timing bars and cell 1's cgroup peak compare
medians across repetitions; the correctness checks and the witness must hold
in every run, any candidate OOM fails cell 1, and the candidate's largest
credit-bytes peak is the one held to its bar. Cell 1 judges the
candidate-only bars (OOM, credit bytes) before reading the parent, so a
parent OOM or bad parent run cannot weaken a candidate FAIL. Cell 6 needs the
candidate's fit and row size in every repetition and reports the median fit.
Exit status is 1 on any FAIL, else 2 on any INVALID, else 0.

A repetition is a directory the runner wrote `provenance.jsonl` into; each
invocation appends its binary hash and cell list. The analyzer reads every
cell a repetition listed. A listed cell that left no result, or only a failure
marker, is INVALID. A paused-reader OOM marker is the OOM verdict even beside
a result, because that cell writes its result before teardown. Any other
failure marker beside a result keeps the result only when it records the
failure (a failed check, an unavailable fit, a dirty probe episode), so an
explicit FAIL stands; beside a result that records no failure it is INVALID,
here and in `check`. A result the directory's provenance does not list is
INVALID, so is a repetition set that differs between the arms, an arm whose
repetitions used different binaries, the same binary on both arms, and a
result whose `cell` or `family` does not match its file name. Measured results must have the
fixed shape on both arms: cell 2 150 receivers among 153 registered peers,
150,000 rows, an 80 s pause, a 500 ms UPDATE interval and the ordinary
trigger; cell 1 150 receivers, 37,500 routes, 240 s, 2 s
rounds and the 12 GiB limit; cell 6 150 receivers and 150,000 rows; cell 4
the fixed 9 probe cells. Cell 7 reads the candidate arm only (its bars are
absolute), with 150 receivers among 153 registered peers, 150,000 rows, a
30 s pause and the selection-release trigger.

| Cell | Bar |
| --- | --- |
| 1 | no OOM; candidate cgroup peak ≤ parent peak − 1.5 GiB; candidate credit-bytes peak ≤ 2 GiB + 150 × one 1,024-row pass |
| 2 | witness on both arms; exact wire state, End-of-RIB order and zero resets in every run; candidate `drain_after_resume_ms` ≤ 60,000 in every run (recovery against max(parent × 1.25, parent + 2 s), and the same rule on the drain, are report-only) |
| 3 | no candidate delivery gap over 1 s outside the churn-free window; candidate p99 ≤ parent p99 × 1.10 |
| 4 | zero dirty episodes in every candidate probe cell |
| 6 | report-only |
| 7 owed-drain step | every candidate release run's longest owed-drain step ≤ 50 ms (INVALID today: no instrument) |
| 7 per kind and family | exact wire state, one End-of-RIB after the table, zero resets, churn inside the drain; longest actor turn ≤ 250 ms; healthy gap ≤ 1 s; unicast live whole-table operations 0 from the release on; summed credit peak ≤ 150 × (per-peer credit + one 1,024-row pass) |

**INVALID** means the evidence cannot support a verdict: a missing result,
a correctness-only or reduced run offered as a measurement, a missing
exhaustion witness, a missing instrument (cgroup peak, VmHWM, the candidate's
credit-bytes gauge), a cell-1 scope without the 12 GiB limit or the swap
fence, a cell-1 receiver that disconnected (it frees its queued state), or a
parent OOM. An INVALID cell is not a product result. A wire FAIL stands
without a recovery time: a run that never settled is FAIL, not INVALID.

Every field below must be present and non-null in each run the cell reads;
a missing or null one makes that cell INVALID, never PASS.

| Cell | Result file | Required fields |
| --- | --- | --- |
| 1 | `paused-evpn.json`, every repetition of both arms (or `paused-exit.json` with `oom`) | `mode` = `measured`; `shape.receivers`, `shape.routes`, `shape.seconds`, `shape.round_ms` fixed; `checks.no_session_resets` = true; `not_established` empty; `memory.cgroup_swap_max` = `0`; `memory.cgroup_memory_max` = 12 GiB; `memory.cgroup_memory_peak_bytes`; `memory.vmhwm_kib`; `memory.cgroup_oom_kill`; candidate `memory.peak_credit_bytes` and `row_size_of` |
| 2 | `exhaust-<family>.json`, every run of both arms | `mode`; `shape.receivers`, `shape.rows_per_receiver`, `shape.pause_ms`, `shape.burst_interval_ms`, `shape.trigger`, `shape.registered_peers` fixed; `witness.refused_receivers`, `witness.peak_credit_rows`, `witness.receivers` (and `witness.peak_credit_bytes` and `row_size_of` on a byte-credit tree); `shape.pause_ms`, `timing.release_sent_ms`, `timing.actual_pause_ms`; `healthy_row_size_of`; `witness.plateau` `samples`, `start_ms`, `end_ms`, `min`, `max`, `resume_issued_ms` and `quiet` `readings`, `churn_stopped_ms`, `churn_delivered_ms`, `end_ms`, `min`; `checks.final_state_exact`, `checks.one_eor_before_burst`, `checks.no_session_resets`; `timing.recovery_ms` once every wire check passed; candidate `timing.drain_after_resume_ms` |
| 3 | `exhaust-<family>.json`, every run of both arms | `mode`; `unaffected.injected` and `unaffected.delivered` (nonzero), `unaffected.p99_latency_ms`, `unaffected.max_gap_ms`; candidate `unaffected.max_gap_raw_ms` and `unaffected.quiet_excluded` `from_ms`, `to_ms`, `span_ms` |
| 4 | `probes.json`, every run of both arms | `mode`; `probes` = the fixed 9 cells (`cell`, `shape`, `peers`, `stall_ms`; restart `table`), each candidate cell with `dirty_episodes` |
| 6 | `fill-<family>.json`, every run of both arms, each family | `mode`; `shape.receivers`, `shape.rows_per_receiver` fixed; candidate `estimate.bytes_per_queued_row` and `row_size_of` |
| 7 | `restart-<family>.json` and `restart-churn-<family>.json`, every candidate run | `mode`; `shape.receivers`, `shape.rows_per_receiver`, `shape.pause_ms`, `shape.trigger`, `shape.registered_peers` fixed; `checks.final_state_exact`, `checks.eor_after_every_route`, `checks.no_session_resets`; `actor.slice_max_us.actor_poll`, `actor.turn_longest_ms`, `actor.work_longest_ms`; `witness` (`witness.peak_credit_bytes` and `row_size_of` on a byte-credit tree, else `drain_gauges.peak_credit_rows`); `drain_gauges.peak_operations_live`; `unaffected` as cell 3's candidate; churn variant `churn.withdrawn`, `churn.re_announced`, `churn.started_ms`, `churn.sent_ms`, `timing.release_sent_ms`, `timing.last_eor_ms`; the step line `actor.owed_drain_step_longest_ms` |
| all | `provenance.jsonl` per repetition | `sha256` (one per arm, different between arms) and `cells` |

Before it appends its provenance line, the runner deletes the previous result
and exit marker of every cell it lists, so a rerun into a used directory that
fails, is interrupted or stops at the quiet-host gate leaves nothing stale.

A cell's exit status is the outcome of the checks its result records, so the
paused-reader cell exits nonzero when a receiver is not Established.

Self-tests, no daemon: `cargo test -p rrtransport credit` seeds a dropped
route, a stale route, an extra route (before and after End-of-RIB), an
undecodable UPDATE, a foreign IMET key, a route after End-of-RIB, a misplaced
or repeated End-of-RIB for each trigger and a session reset into the wire
checker, plus, against a churned reference, a surviving withdrawn route, a
stale re-announcement and a route outside the churn after the End-of-RIB;
it also checks the gap exclusion, that a plain registry read misses the
since-render slice maximum the harness keeps, and the histogram brackets.
`python3 -m unittest discover -s
bench/scale/rrtransport -p 'test_*.py'` seeds each bar's defect into the
analyzer and checks that only that cell changes verdict (owe-whole flips
without spent credit and a restart burst offered as cell 2 are both INVALID;
so are a null owed-drain step instrument, a long poll with no provably long
turn and churn outside the drain),
removes each required field in turn, and drives the runner with a stand-in binary to check that a
rerun clears stale results.
