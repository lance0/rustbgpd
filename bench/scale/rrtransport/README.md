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

## Established route-server clients at first refusal

The `grouped-old-capture` cell measures the ordinary RIB turn that saves an
established group member’s previously admitted unicast keys (OLD). Use the
supervised runner to collect cgroup and compiler evidence alongside the actor
receipt. It accepts a prebuilt scale-profile binary and a fresh output directory.

```sh
CARGO_INCREMENTAL=0 cargo build --locked --profile scale -p rrtransport
bench/scale/rrtransport/run-grouped-old.sh target/scale/rrtransport /tmp/grouped-old-smoke smoke
```

| Runner shape | Established group clients | Routes before the trigger |
| --- | ---: | ---: |
| `smoke` (correctness only) | 4 | 64 |
| `smoke-chunked` (multiple seed and recovery batches, correctness only) | 12 | 2,049 |
| `150x37000` | 150 | 37,000 |
| `700x400000` | 700 | 400,000 |

Each client is a real IPv4 loopback eBGP route-server session. The clients share
one remote ASN and a prefix-deny/default-permit export policy. A denied route
must win locally and remain absent from every receiver. The two sources submit
session-scoped route batches at the RIB boundary. The harness controls
each member's outbound channel so every target can start the measured turn
with a full writer and a previously clean view. A separate source submits one
ordinary unicast UPDATE at the start of the first capture. The primary-lane
clock ends when the actor enters that UPDATE’s handler. The subsequent
observation of its matching Loc-RIB winner is an upper bound on application.
The capture clock runs from the first OLD walk until the pre-staging loop
returns. The receipt records the triggering pass, its enclosing physical RIB poll,
and the longest physical RIB poll through the post-recovery barrier separately.
The enclosing poll includes any other work done in that poll.

The witness counts fresh grouped proofs that sealed, completed table walks,
and actual member projections in the selected pass. A capture includes a
sizing walk and a population walk on the current implementation. A successful
run must exercise fresh capture for every target, through the same turn as
the unrelated probe. Missing or zero work evidence makes the run INVALID.
Independent checks fold both accepted RIB envelopes and decoded TCP UPDATEs.
After recovery each client must have the correct keys, origin, next hop, AS path
and communities, including the replacements and the final withdrawal. Each
stream is checked at a decoded IPv4 ROUTE-REFRESH fence. A wrong table or a
session reset fails the run. The controlled quantity is backpressure at the
physical sender's RIB queue, not the time for a TCP socket to fill.

The counters and probe hook require `bench-internals`; the normal daemon
exports no metric for them. Optimized runs require the test checkpoint tally
to be compiled out. The elapsed times include the bench observation itself.

Grade a saved directory with
`python3 bench/scale/rrtransport/grouped_old.py check OUTPUT_DIR SHAPE`. The files `grouped-old.json` and `host.json` retain
per-receiver wire evidence, actor clocks and work counts, and the cgroup and
compiler observations. The runner records the executable SHA-256 and uses the
quiet-host gate for the two full shapes. It samples for compilers every 250 ms
and at the process boundaries.

Every shape uses a dedicated 64 GiB cgroup with swap disabled. The receipt
records kernel memory peak and swap peak and watches for a compiler throughout
the run. The limit is a fence, not a prediction of memory use. An OOM or
incomplete capture leaves that size unqualified. The full shapes report
measurements without a predeclared latency pass/fail threshold.

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

Each cell reports the independent sampled peaks of jemalloc allocated, active,
and resident bytes. `memory.at_peak_sampled_rss` records all three from the
first sample at the highest observed process RSS (`peak_sampled_rss_kib`).
Linux records `VmHWM` separately and can see a higher peak between samples.
Both analyzer commands print these as report-only readings, with the paired
RSS and `vmhwm_kib` beside them. An unavailable reading prints as `n/a`. This
includes a field absent from an older receipt and a gauge that reads 0, which
the allocator never refreshed. Readings that break jemalloc's order (resident
at least active, active at least allocated) read INVALID.

- *allocated*: bytes in live allocations.
- *active*: allocated plus the unused space in the pages those allocations
  occupy (fragmentation).
- *resident*: jemalloc's upper bound on its resident pages: metadata, active
  pages and unused dirty pages. It counts pages the process never touched, so
  it can exceed the RSS of the same sample.

"Resident minus allocated" therefore over-attributes memory to allocator
retention unless it is compared with the RSS of the same sample.

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
the gap calculation leaves it out: from when the last churn row sent before
the stop arrived (`quiet.churn_delivered_ms`, never earlier than the stop) to
when the churn restarted, recorded as `unaffected.quiet_excluded` (`from_ms`,
`to_ms`, `span_ms`), with the configured lead as `unaffected.quiet_lead_ms`.
A slow delivery of that last row therefore stays in the gap. When it never
arrived nothing is excluded (`quiet_excluded` is null and the gap is the raw
one). The window's RIB waits (the churn's stop and the queries that republish
the gauges) end at most 5 s past its end, measured from the end and not from
when the window started: a window that starts late, behind a held read at its
own cap, gets only what remains of those 5 s, possibly none; past that the
window is unavailable
(`quiet.unavailable` set, no readings, `quiet_excluded` is
`{"unavailable": ...}`), the cell still resumes its readers, and bar 3 and the
plateau are INVALID: an unknown span is not "nothing excluded".
A gap counts only its part outside that span, so the last row's
delivery before the window and the first row's after it still count. An
excluded span over twice `quiet_lead_ms` is INVALID: it could hide a stall. `unaffected.max_gap_ms` is
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

The analyzer also checks arm identity: the parent is a row-credit tree, so
a parent exhaustion result with `bgp_rib_outbound_credit_bytes` makes cells
2 and 3 INVALID (a byte-credit candidate in the parent's place). The
candidate may charge rows or bytes. Two builds of one tree, row-credit or
not, are refused by the binary hashes (every cell INVALID). A row-credit
pair swapped is not visible here; cell 7, which reads only the candidate,
fails an uncharged parent tree in the candidate's place on its credit
witness. `witness.receivers` must equal `shape.receivers`. On a row-credit
tree the per-peer credit comes from the result's `row_credit` record: the
RIB's crate-private constants (`DAEMON_ROW_CREDIT`, `MIN_ROW_CREDIT`,
`MAX_ROW_CREDIT`, `CHUNK_ROWS`), which the harness mirrors and a harness
test compares with `crates/rib/src/outbound_credit.rs`.

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

The opt-in `restart-labeled4` and `restart-labeled6` cells run SAFI 4
separately for IPv4 and IPv6. Each measured cell has 150 ungrouped,
labeled-only, single-best receivers with identical private export policy,
150,000 rows and a 90 s reader pause. Every prefix has one label.
The fixture loads the source's table, checks
that graceful restart retained it, and replays it on the replacement session.
A second GR peer keeps selection held until replay is complete. Its
End-of-RIB releases the family while the labeled readers are paused.
Each receiver must decode the expected prefixes, MPLS labels, next hops and
MEDs before its single family End-of-RIB. Once every receiver has the table, the source withdraws
one advertised prefix. Each receiver must decode that withdrawal and
retain every other row. The withdrawal check is outside the recovery clock.

Run both reduced correctness cells and check the expected drain mechanism for
the binary under test. Use `whole` for the whole-family implementation and
`cursor` for the row cursor.

```sh
bench/scale/rrtransport/run-credit-cells.sh --reduced --correctness-only \
    target/scale/rrtransport /tmp/labeled-smoke restart-labeled4 restart-labeled6
python3 bench/scale/rrtransport/credit_bars.py check-labeled whole /tmp/labeled-smoke
```

For A/B, compare the integrated cursor revision with the same main revision
it was based on. Overlay the same `bench/scale/rrtransport` sources on both
trees, check their directories with `diff -qr`, and build each with a
separate Cargo target directory. Save both product revisions and the harness
revision with the campaign. The runner records the binary SHA-256 in
`provenance.jsonl`. Omit both smoke flags for a measured run. Use the
same repetition directory names under each arm.

```sh
python3 bench/scale/rrtransport/credit_bars.py labeled PARENT_DIR CANDIDATE_DIR
```

The labeled comparison checks both AFIs in each arm, then reports the ratio
of candidate to parent arithmetic means for each AFI. A whole-family run
must record one whole step per receiver. A cursor run must record at least
`receivers × ceil(rows/1024)` cursor steps. Other scopes must record zero
steps. Each receipt shows the counts while reads were paused and through
the last End-of-RIB, along with the longest step's histogram bucket.
The campaign sets the performance thresholds.

Recovery has two clocks, release to last decoded End-of-RIB and reader
resume to that marker. After the final receiver decodes its marker, the
harness reads the poll maximum between RIB polls. This includes the whole
poll that offered the marker, even when the receiver decoded it before
that poll returned. The single unrelated IPv4 UPDATE samples the
release turn. It is queued behind the releasing marker between actor polls.
The receipt timestamps the first lookup returning its matching winner
(an upper bound on installation) and delivery to a separate TCP receiver.

Every cell runs in a fresh cgroup with `memory.swap.max=0`. Its
`memory.peak` includes the harness and its decoded-message queues. The
receipt records each stub's maximum observed queue depth in messages,
sampled just after dequeue. These samples can miss a transient maximum,
occur at different times across stubs, and cannot bound the queue's bytes.
The relative peak memory reading is report-only.

`credit-restart-churn` adds churn while the release drains. Halfway to the
churn-free window (14.85 s into the pause on the full shape), with the
release queued ahead of it and every burst reader still paused, the source
withdraws every 100th burst route (1,500) and then re-announces every other
one of those (750) at MED 9. The reference is the post-churn table:
withdrawn routes absent, re-announced ones at MED 9, the rest at MED 7. A
churned route may arrive on either side of the End-of-RIB (a withdrawal
behind the marker is an ordinary UPDATE); every other route must precede
it, and `wire.withdrawn_survivors` counts withdrawn routes a receiver still
holds at the end (also a `final_state_exact` failure). The churn must
withdraw and re-announce (both counts nonzero) and be sent after the release
and before the readers resume and the last End-of-RIB (`churn.started_ms` at
or after `timing.release_sent_ms`, `churn.sent_ms` before
`timing.resumed_ms` and `timing.last_eor_ms`); otherwise the run is INVALID.
Those timestamps cannot show that the churn reached the RIB while it still
owed the table: the last End-of-RIB is decoded after the resume whatever
happened. The wire does: per burst receiver,
`wire.churn_reflected_before_eor` counts churned routes whose state before
its End-of-RIB already reflected the churn (a withdrawn route never
announced before the marker, a re-announced one first seen at MED 9). At the
full shape (150 receivers, 150,000 rows) a receiver with none is INVALID,
"churn did not land in the drain", in `check` and in the analyzer; on the
reduced shape the release may drain before the churn, so `check` only
reports the counts. `wire.duplicates_before_eor` counts announcements before
the End-of-RIB that repeat the MED already held; it is reported, not gated.

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
  `bgp_rib_outbound_owed_drain_step_seconds`, keyed by its `scope` label:
  `cursor` (up to one 1,024-key pass of a unicast family owed whole, sent
  as a charged ordinary envelope), `keyed` (up to one pass of an owed-key
  set) or `whole` (one whole-family pass, including one absorbed for a
  waiting End-of-RIB). Where the histogram also carries a `family` label,
  each key is `scope/family` (for example `cursor/l2vpn_evpn`); bar 6 reads
  from these keys how the run drained its family. A scope or family label
  outside the product's closed vocabularies (`OWED_DRAIN_STEP_SCOPES` and
  the canonical family labels in `crates/telemetry/src/metrics.rs`) makes
  bar 6 INVALID, naming it. A tree that times
  owed-drain steps exports it from `RibManager::owing_drain_step` (`crates/rib/src/manager/outbound_owing.rs`)
  with the stall buckets (exact edges at 50 and 250 ms); on a tree without
  it the field is null. There the drain's readiness checkpoints are
  unnamed, so its slices fall in stage `other` with every other unnamed
  checkpoint and are cut at every 64th checkpoint, not at step boundaries.
- `actor.eviction_recovery_longest_ms` reports the count and longest
  duration bracket from `bgp_rib_outbound_eviction_recovery_seconds` for
  each observed data commit outcome (`processed` or `commit_refused`).
  Each sample times one receiver's whole-table recovery build in the RIB.
  An owed-row cap eviction triggers this build. A dirty resync that leaves
  EVPN state to rebuild during a selection hold also triggers it after release.
  Both triggers share the same outcome series.
  An empty object means the run observed no build. A null means its binary
  lacked the instrument. The report identifies the cell, repetition and arm
  in paired analysis, or the result path in a single-arm check, and gives
  the run mode. The credit cells can finish without reaching the cursor cap.
- `drain_gauges`: from the release (`from_ms`) to the cell end, the getter
  values of `bgp_rib_outbound_operations_live` and
  `bgp_rib_outbound_credit_rows`, read every 1 ms (`reads`, up to
  `to_ms`): the peak of each, and the first and last reading with a live
  operation. The RIB
  publishes both once per run-loop iteration, so a value that lives inside
  one iteration is invisible. The live-operation gauge is unlabeled: it
  counts every family's whole-table operations, at most one per peer. In a
  release cell only the cell's family is owed, so in one whose family the
  run drained by cursor every whole-table operation is that family's; in
  one whose family drains whole the peak is reported, not gated. On a tree
  with `bgp_rib_outbound_credit_bytes`, the watch also reads that gauge
  by name, aiming at every 1 ms (`peak_credit_bytes`, over
  `credit_bytes_reads` reads; null and 0 on a tree without it). No tree has
  a getter for it on every arm, so each read is a registry gather, over a
  millisecond on the reduced shape; it runs on its own thread so the getter
  reads keep their period, back to back when a gather outlasts it.
  `credit_bytes_watch` says how it went: `watched`, `not exported`,
  `exported after start` (the gauge was absent when the watch started, as
  a labeled family is until its first child, so nothing read it) or
  `failed`. The byte watch thread runs only on an arm that exports the
  gauge, so in a comparison of a row-credit parent with a byte-credit
  candidate it loads the two arms unequally.
- `witness.held` (release cells; null elsewhere): one read with every burst
  reader paused, just before the churn-free window (`at_ms`), bounded at
  5 s; past that it records only `unavailable` and the cell resumes its
  readers. It does not read the credit gauge to find the held rows:
  `advertised_rows` sums every burst receiver's Adj-RIB-Out count of the
  burst family (the RIB records a row there when it admits the envelope
  carrying it), and `read_rows` sums the rows the receivers decoded. For
  unicast the counts are one `QueryAdvertisedCount` a receiver, all queued
  at once (O(1) a private peer); EVPN has no O(1) per-family count, so it
  reads `QueryBmpPeerStats`, which walks every peer's Adj-RIB-Out in one
  turn. `charged_before` and `charged_after` are the summed credit-rows
  gauge, republished, before and after those queries. `writer_bytes` is
  `bgp_outbound_writer_bytes` (encoded, not yet written to a socket) and
  `socket_bytes` the send and receive queues of the burst receivers'
  connections in `/proc/self/net/tcp` (written, not yet read), picked by
  the stub's listening address and port at either end; `socket_ends` is how
  many connection ends matched (null, with `socket_bytes`, when none did or
  the table was unreadable). Those receive queues are the harness
  receivers' kernel buffers: decoded-row credit, the session writers'
  buffers and kernel socket memory are separate terms. A session drops an
  envelope, and its charge, once it has encoded it, so those bytes are the
  held rows the charge no longer covers. The count is of routes, not rows:
  in the churn variant a route withdrawn while held is in no Adj-RIB-Out
  count while its announcement and withdrawal may both still be charged,
  and a re-announced one counts once against up to two charged rows. Churn
  can therefore only lower held against the charge, by up to receivers ×
  (2 × `churn.withdrawn` + `churn.re_announced`) rows, which loosens the
  witness in that cell and never trips it.
- `wire.min_row_bytes` and `wire.max_row_bytes`: over every UPDATE a burst
  receiver decoded that announced a row, the fewest and most bytes per
  announced row (the message less its withdrawn routes), rounded down;
  `wire.max_rows_per_update` is the most announced rows in one UPDATE. Each
  receiver's entry under `receivers` records the same three. The burst's
  attributes differ per route, so each UPDATE carries one row.
- `actor.inbox_round_trip`: from the release (`from_ms`) until every burst
  receiver is exact (`to_ms`), one `QueryLocRibCount` (a length read)
  through the RIB's update channel every 10 ms, sent from the harness
  runtime on both arms: the number of answered probes, the longest wait for
  a reply and when that probe was sent. A drain that yields between steps
  without serving that channel shows as a long round trip even when every
  poll is short. Each probe (send and reply) waits at most 30 s (`cap_ms`);
  one still unanswered there ends probing with `unfinished: true` and its
  wait so far as the longest, so a RIB that stops serving the channel
  cannot hold the cell's result back.

The cell-7 bars read the candidate's measured fixed-shape runs only:

- Bar 1, its own line over every release run: the longest owed-drain step
  at most 50 ms. PASS when every bracket's `at_most_ms` is at most 50, FAIL
  when an `above_ms` is at least 50, otherwise INVALID; INVALID "no
  instrument" while the field is null (a tree without the histogram).
- Bar 2: the longest RIB actor turn during the release and its drain, over
  the whole run window, at most 250 ms. FAIL when a turn or work unit's
  `above_ms` is at least 250. PASS when `slice_max_us.actor_poll` is at most
  250,000 and the longest inbox round trip at most 250 ms. Otherwise
  INVALID: an unfinished probe ("probe unfinished": evidence of a wait over
  the bar that no turn instrument confirms), a poll of 0 or no probe (dead
  instrument), no `end_of_rib` turn in
  the window, a longer poll with no turn provably over the bar (a poll may
  hold many short turns), or a poll within the bar with a longer round trip
  ("instruments disagree": the bar is on the turn, so the probe can withhold
  a PASS but not FAIL on its own).
- Bar 3: the healthy receiver's longest delivery gap, outside the
  churn-free window, at most 1 s.
- Bar 4: the wire checks above, and for the churn variant its timing and
  wire witness (INVALID otherwise).
- Bar 6: the 1 ms gauge watch ran, at least one read per two `read_every_ms`
  of its window (INVALID otherwise); and the summed credit-rows peak is at
  most receivers × (per-peer row credit + one pass): 150 × (109,655 +
  1,024). The run itself says how it drained the cell's family: its
  owed-drain step histogram (`actor.owed_drain_step_longest_ms`), counting a
  key labeled with another family as that family's and an unlabeled key as
  the cell's own (only the cell's family is owed in a release cell). Where
  the run recorded `cursor` steps for the family, the candidate drains it
  in charged ordinary envelopes, so `drain_gauges.peak_operations_live` must
  be 0 and the charging witness below gates. Where it recorded only `whole`
  steps, its whole-table operations charge no rows by design: the witness
  and the live operations are report-only, and the line names that reason.
  Both scopes for the family (a partial move) or neither is INVALID, and so
  is a candidate run without the histogram (null, as on a tree without it),
  like bar 1. A family the candidate must drain by cursor (unicast always;
  `analyze --require-cursor FAMILY` adds one) FAILs when its run recorded
  steps for it but no `cursor` step, naming the scopes it saw. `check` reads
  a run without the histogram as a tree that predates it, where unicast
  drains by cursor and EVPN whole. On main unicast records `cursor` steps
  and EVPN `whole` ones; a campaign whose candidate moves EVPN onto the
  cursor passes `--require-cursor evpn`, so a candidate that still drains
  it whole FAILs instead of reporting its witness.
  The charging witness: every
  row held toward the paused receivers must be charged (`witness.held`):
  held = `advertised_rows` − `read_rows` may exceed the charge
  (`charged_after`) by at most the rows the sessions already encoded,
  (`writer_bytes` + `socket_bytes`) / `wire.min_row_bytes` rounded down,
  or FAIL "owed rows not charged". Nothing else is added to that slack: an
  envelope part encoded is both charged and queued, and rows admitted after
  the held read are charged and held nowhere, which only loosen the check.
  The read is INVALID when it is unavailable, outside the pause, not tight
  (the charge moved by more than receivers × one pass either way across
  it), when `socket_ends` is not 2 × receivers, when the row size is not
  uniform (an UPDATE carried more than one announced row, or
  `wire.max_row_bytes` exceeds `wire.min_row_bytes` by more than 1%), and
  when held fits the slack: there a missing charge cannot show. Its
  detection limit is observed, not proven, and only for the unicast shape:
  no EVPN or byte-credit-tree detection limit has been measured. On one
  unicast cursor-drain tree at
  150 × 150k (correctness-only runs), three clean full-shape reads left
  margins of 105,979, 106,636 and 120,831 rows (slack less held − charged),
  so in those runs a missing charge above about 106,000 rows (1.1% of the
  charge) would have shown; the first held 12,029,952 rows against a
  9,879,552-row charge with a slack of 2,256,379. The same tree failed with
  every fourth cursor envelope uncharged (4,611,072 rows held over its
  charge; 4,458,496 under churn) and with nothing charged (11,959,296;
  11,979,776). That margin is what these runs showed for this shape and
  snapshot, not a bound proven for every sampling interleaving. The RIB's
  envelope-accounting unit tests
  (`crates/rib/src/manager/tests/outbound_credit.rs`) are the accounting
  proof; this witness is an independent check on a running drain. The
  witness does not ask the charge to reach the credit:
  backpressure can stop a charged drain short of it. One cursor-drain tree
  peaked at about 150 × 67,000 rows at the fixed 30 s pause, still staging
  when the readers resumed, and held exactly 150 × 109,655 when paused
  75 s (a correctness-only run). Whether the peak reached receivers ×
  (credit − one pass), 150 × (109,655 − 1,024), is reported only. A
  byte-credit tree keeps the credit-rows gauge and its meaning, so it takes
  the same rows checks: the rows bound, and the charging witness for a
  family it drains by cursor. Its byte bound reads the byte watch's peak
  (`drain_gauges.peak_credit_bytes`): at most receivers × (per-peer byte
  credit + 1,024 × (`row_size_of` + 146)), 150 × (14,035,840 + 1,024 × 250)
  for unicast at 2 GiB, from the run's record of its tree's byte credit
  (`byte_credit`: `DAEMON_CREDIT_BYTES`, `MIN_CREDIT_BYTES`,
  `MAX_CREDIT_BYTES`). A peak the watch read over it FAILs even if its read
  count is missing. A run that records byte limits but has no byte gauge is
  INVALID. Otherwise the bound must be able to gate, or bar 6 is INVALID:
  a `byte_credit` record
  (this harness records none, because the byte tree keeps those constants
  crate-private and exports no limit, so a byte-credit candidate is INVALID
  here), rows of one size (the witness's uniform-row check), a byte watch
  that saw the drain (`credit_bytes_watch` `watched` for any byte peak,
  not only the 250 ms sampler; a `watched` run with no byte reading is
  INVALID, not a row-credit tree) and at least one byte read per 10 ms of its window on average;
  the line names the actual reads and interval.

Each bar of each run is judged on its own, so a FAIL in any of them stands
even when another bar or another run lacks an instrument. A repetition that
attempted the cell and left no result, or a result of the wrong mode or
shape, is undecided evidence in the same way: a FAIL in another run still
stands, and when nothing failed the line is INVALID, never PASS.

The opt-in release cells exercise ordering with two continuously reading
loopback receivers and 64 routes per family (16 with `--reduced`).

- `release-mixed` negotiates IPv4 unicast and EVPN on both receivers. It
  verifies their shared unicast group, sends each source End-of-RIB in
  turn, and reads the whole-family debt counter after each release. Unicast
  adds zero debts and EVPN adds one for each receiver.
- `release-timer` leaves the IPv4 source End-of-RIB outstanding. It checks
  that the selection gate still has its waiter after ingest and that the
  RIB recorded a timer release. Both private receivers must get the exact
  table followed by one End-of-RIB.
- `release-vpn4`, `release-vpn6`, `release-labeled4` and `release-labeled6`
  negotiate one address family per session. A typed RIB source stages the
  routes, then releases selection by sending its End-of-RIB. Each private
  receiver decodes the outbound TCP stream. It must receive every expected
  prefix with its label stack, next hop and MED, followed by exactly one
  End-of-RIB for the negotiated family. VPN rows alternate between two
  route distinguishers that share each inner prefix. An unexpected route,
  withdrawal, marker or session reset fails the cell. These fixed-size
  fixtures cover initial release with continuously reading peers.

Each JSON file records the receiver observations and `release_ms`, from
the post-ingest observation to the last family End-of-RIB. This includes
the remaining deferral interval in the timer cell. A missing marker leaves
the duration null. The `analyze` and `check` commands print these cells as
REPORT. Their checks do not change the campaign verdict.

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

### Unpaced source burst through real sessions

The cells above inject their sources' routes straight into the RIB's
channel and pace the ordinary burst, so they cannot see what a session does
with a peer that sends faster than the RIB distributes. `credit-source-burst`
(runner cell `source-burst`) covers that path. Both sources are stub peers
over TCP loopback, so every route passes the production session read path
and its admission into the RIB:

- the burst source writes 150,000 unicast routes, 1,024 to an UPDATE, as
  fast as its socket accepts them, then withdraws every 100th route and
  announces every other one of those again at a new MED. 1,024 is the RIB's
  route chunk and the distribution window's affected-prefix bound, so each
  burst message is one window, as one from a production peer of that size
  would be. Such a message is past 4,096 bytes, so the burst source
  negotiates Extended Message (RFC 8654) with its session; the other stubs
  do not;
- 150 private receivers read normally and must end with exactly that table;
- a healthy source sends one single-route UPDATE every 20 ms from 500 ms
  before the burst until 300 ms after it settles, toward one more receiver
  that gets nothing of the burst.

`--reduced` runs 8 receivers, 16,000 routes and a 5 ms healthy cadence.
`--rows N` sets the burst size and marks the run a correctness run.
`--routes-per-update N` sets the UPDATE size (see Small UPDATEs below).
`--control` (runner cell `source-burst-control`) sends no healthy update and
records the burst's uncontended ingest rate.

Runner cell `source-burst-two` (`credit-source-burst --two-sources`) splits
the reduced plan's 16,000 routes evenly between two loopback sessions. It
uses the same eight receivers, UPDATE size, churn subset and healthy cadence
as `source-burst --reduced`. A smaller `--rows N` selects the same total
work for either run. Each of the plan's three stages (announce, withdraw,
announce again) can gain an UPDATE where the split cuts a chunk: 20 messages
for the single source's 18 at 16,000 routes. Both writers finish their first
socket write before either continues. Per source, the receipt records the
prefix count and range its UPDATEs carry (read back from the planned wire
messages), message counts, when its first write finished and when it went
on, write completion and the RIB's final marker. The analyzer requires
disjoint ranges that sum to the table, at most three messages more than the
single-source plan, and no writer going on before the other's first write. Each burst receiver must converge on the combined table
and the healthy receiver on its last sent /24 and MED. A writer the session
stops reading gives up at the deadline, so the result is still written. When
one source was admitted in full and the other was not, the cell reads FAIL on
`sources_complete` ahead of the tap-recognition INVALID. The two-source cell
is opt-in and correctness-only.

**Stamps.** The harness owns the channel between the sessions and the RIB
and puts a forwarding tap on it. Sessions admit into the tap's ingress
channel; one dedicated thread forwards every message in order into the RIB's
channel. Each half holds 2,048 messages, so together they hold what the
daemon's 4,096-message channel holds. Per healthy update the result records,
in ms from the start of the healthy cadence:

| Column | Taken |
| --- | --- |
| `sent_ms` | by the healthy source before it hands the UPDATE to its writer |
| `admitted_ms` | when the session's message reaches the tap |
| `dispatched_ms` | when the RIB answers a `QueryLocRibCount` marker the tap sends immediately ahead of the update; the primary lane is served in order, so this is when the RIB reached the update's place in the queue |
| `received_ms` | when the healthy receiver decodes that sequence, or a later one that replaced it |
| `burst_ahead` | burst messages sent before the update that the RIB had not finished when it was admitted, the one it was serving included |
| `queue_depth` | all messages in the RIB's channel at that moment |

A marker behind every burst message tells when the RIB finished it; those
stamps give `burst_ahead`, and the last gives `burst.rib_done_ms`. The
readings are admission to dispatch (the time queued behind earlier work),
dispatch to receipt (the update's own distribution pass) and send to receipt.

Limits of the instrument:

- The tap adds one thread hand-off to admission.
- A marker is not route input, so it ends the distribution window ahead of
  every healthy update: healthy updates never coalesce with each other, as
  contiguous healthy updates in production would. The markers behind burst
  messages end no window, since a 1,024-route message closes its own.
- The dispatch and finish stamps are taken when the stamper thread wakes,
  a little after the RIB answers. The healthy receiver can decode an
  update before its dispatch stamp (by up to 0.21 ms in debug runs), so
  dispatch to receipt can read slightly negative; a burst message finished
  within that time of an admission can count as still ahead.
- Each healthy update and its marker take two slots in the RIB's half of
  the channel, so it holds 1,024 healthy updates rather than 2,048, and the
  two halves together about 3,072 rather than the daemon's 4,096. Once the
  RIB's half is full, later messages wait in the ingress half unstamped
  and their readings start late;
  `healthy.stamped_late` counts them. The longest reading is the update
  admitted first behind the burst, which is unaffected.

**Verdict.** `credit_bars.py` judges each result. It FAILs when a
correctness check failed: every burst receiver's table exact and the last
healthy sequence delivered (`final_state_exact`), burst messages admitted in
the order sent and healthy sequences admitted and received in order
(`per_source_order`), every session Established with no reset or flap
(`sessions_established`). It is INVALID when the instrument could not have
seen a healthy update queued behind the burst, or its timing is unusable:

- the burst was paced (`shape.burst_interval_ms` or `burst.paced_sleep_ms`
  above zero);
- a healthy update lacks a stamp, has stamps out of order, or a marker was
  never answered;
- fewer than three healthy updates were admitted while the burst was
  unfinished;
- the run carried a seeded stall;
- a measured run is not the fixed shape, saw a compiler (`cargo`, `rustc`,
  `rustdoc`, `clippy-driver`, sampled every second during the cell), or
  could not read the process table.

A run is also INVALID when the tap did not recognize every burst message
the source sent (a new message variant would leave it blind, and the run
waits out its deadline), or when a dispatch stamp trails the healthy
receiver by more than 50 ms (the stamper stalled). A flap, stub reset or
session not Established recorded under `wire` FAILs the run even where
`sessions_established` reads true: it is the daemon's behavior, not the
instrument's. Such a record, or `sessions_established` false, FAILs before
any INVALID reason is weighed, so a burst source that went down before its
last UPDATE fails although the tap missed the messages it never sent. The
table and order checks, which follow the tap, FAIL only once the tap
recognized the whole burst.

Otherwise it PASSes and prints the readings: the longest and median
admission-to-dispatch time, the most burst messages queued ahead, the
longest send-to-receive and dispatch-to-receive times, how many admission
stamps were late, when the burst finished in the RIB and on every receiver,
routes per second, the bucket edges around the longest `distribute_flush`
pass, and peak RSS (the result also carries the cgroup peak). All of these
are report-only; no bar is frozen. Nothing requires that a queue formed:
a parent whose burst never queued a healthy update, or a long wait with no
burst message ahead of it, still PASSes with those readings in its line.
`analyze` adds a REPORT line with the candidate's readings over the
parent's.

**Seeded defects.** `--stall-ms N` holds healthy update 5, inside the lead,
for N ms between its admission stamp and its marker; the analyzer prints
the stalled reading beside the other pre-burst updates. It proves the stamp
arithmetic: a delay between the two stamps reads as that delay. It sleeps
on the tap's thread, so it says nothing about time spent in the RIB.
`--burst-interval-ms N` paces the burst. Either marks the run a correctness
run and INVALID.

**RIB-side residence.** `--rows N` proves that the reading follows time
spent queued in the RIB: the first healthy update admitted behind the burst
waits for all of it, so doubling the burst roughly doubles the longest
admission-to-dispatch time. This is a manual check, not a CI gate. One
debug build, `--reduced`, on one host (all runs PASS):

| `--rows` | Runs | Longest admission to dispatch, median (range) | Burst finished in the RIB, median |
| --- | --- | --- | --- |
| 16,000 (the default) | 20 | 903 ms (882–925 ms) | 957 ms |
| 32,000 | 10 | 1,934 ms (1,833–2,346 ms) | 1,994 ms |

The ratio is 2.14 for the reading and 2.08 for the burst.

**Small UPDATEs.** A production peer often sends tens to a few hundred
routes per UPDATE, not 1,024. `--routes-per-update N` (1 to 1,024; default
1,024) sends the same burst in UPDATEs of N routes, the last of each stage
carrying the remainder, so the burst takes ceil(routes / N) messages per
stage. Such a run is its own shape: its result is named
`source-burst-small` (or `source-burst-small-control`) and records N as
`shape.rows_per_update`. The runner cells `source-burst-small` and
`source-burst-small-control` run it at N = 100, only when named. The shape
measures how the session's admission and the RIB's distribution window
interact when one window holds several of the source's messages: a window
closes at 256 messages, 1,024 affected prefixes or 5 ms, so at N = 100
about ten burst messages share one. The burst source negotiates Extended
Message only when a message is past 4,096 bytes, so at N = 100 it does not.

At small N the instrument changes in three ways:

- A marker behind every burst message would end every window after one
  message. The tap instead puts a marker behind the message that brings a
  window begun after the previous marker to 1,024 distinct prefixes (a
  prefix withdrawn and announced again in the churn tail counts once),
  4,096 route entries or 256 messages, where the RIB closes it anyway, and
  behind the last (`shape.burst_markers`).
  A window that a healthy update or the 5 ms bound started mid-group still
  ends at the next marker, short of its bound.
- `burst_ahead` counts a message as ahead until its group's marker is
  answered, so it can read up to a group's messages high; the verdict line
  says so when markers are fewer than messages.
- Every burst message and every marker takes a slot in the RIB's half of
  the tap. A result whose burst messages and markers together exceed that
  half's 2,048 slots is INVALID, since admission stamps after it fills would
  read late. The full shape at N = 100 needs about 1,660 slots.

The verdict line prints the number of distribution passes in the run; for
a control, which has no healthy updates, every pass is the burst's, so the
line also prints burst messages per pass. A measured run must have N =
1,024 for the default cells and below 1,024 for the small ones. `analyze`
compares a cell only between runs with the same N: runs with different N
are different shapes and the comparison line is INVALID.

### Running

Build one binary per arm from its own tree, and check that the two differ.
The harness links the tree's RIB, so each arm's binary is that tree's
daemon code driven by this harness: both trees must contain this version of
`bench/scale/rrtransport/` (merge it, or copy the directory into a parent
tree that predates it). A result from an older harness lacks the
`row_credit` record and makes its row-credit cells INVALID ("no row_credit
record ... build both arms with this harness").

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
| 7 owed-drain step | every candidate release run's longest owed-drain step ≤ 50 ms (INVALID on a tree without the histogram: no instrument) |
| 7 per kind and family | exact wire state, one End-of-RIB after the table, zero resets; churn variant: both kinds of churn, sent between the release and the resume, and on every receiver a churned route already in its post-churn state before its End-of-RIB; longest actor turn ≤ 250 ms (PASS needs the poll and the inbox round trip within it); healthy gap ≤ 1 s; credit-rows peak ≤ 150 × (per-peer credit + one pass); for a family the run recorded `cursor` owed-drain steps for, live whole-table operations 0 from the release on and rows held toward the paused receivers no more than the charge plus the rows already encoded (report-only where it recorded only `whole` steps; INVALID with both, neither or no histogram); a family that must drain by cursor (unicast; `--require-cursor` adds one) FAILs without a `cursor` step; byte bound ≤ 150 × (per-peer byte credit + one pass) on a byte-credit tree, INVALID without the run's `byte_credit` record, uniform rows, a complete byte watch or one byte read per 10 ms |

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
| 3 | `exhaust-<family>.json`, every run of both arms | `mode`; `unaffected.injected` and `unaffected.delivered` (nonzero), `unaffected.p99_latency_ms`, `unaffected.max_gap_ms`; candidate `unaffected.max_gap_raw_ms`, `unaffected.quiet_lead_ms` and `unaffected.quiet_excluded` (present; null, with `from_ms`, `to_ms`, `span_ms`, or `unavailable`: INVALID) |
| 4 | `probes.json`, every run of both arms | `mode`; `probes` = the fixed 9 cells (`cell`, `shape`, `peers`, `stall_ms`; restart `table`), each candidate cell with `dirty_episodes` |
| 6 | `fill-<family>.json`, every run of both arms, each family | `mode`; `shape.receivers`, `shape.rows_per_receiver` fixed; candidate `estimate.bytes_per_queued_row` and `row_size_of` |
| 7 | `restart-<family>.json` and `restart-churn-<family>.json`, every candidate run | `mode`; `shape.receivers`, `shape.rows_per_receiver`, `shape.pause_ms`, `shape.trigger`, `shape.registered_peers` fixed; `checks.final_state_exact`, `checks.eor_after_every_route`, `checks.no_session_resets`; `actor.slice_max_us.actor_poll`, `actor.turn_longest_ms`, `actor.work_longest_ms`, `actor.inbox_round_trip.longest_ms`, `probes` and `unfinished`; `witness` (an object); `row_credit` (all four constants); `drain_gauges` `from_ms`, `to_ms`, `read_every_ms`, `reads`, `peak_credit_rows`, `peak_operations_live`; `actor.owed_drain_step_longest_ms` (bar 6 reads how the family drained from it); for a family drained by cursor `witness.held` `at_ms`, `advertised_rows`, `read_rows`, `charged_before`, `charged_after`, `writer_bytes`, `socket_bytes`, `socket_ends`, and `wire.min_row_bytes`, `wire.max_row_bytes`, `wire.max_rows_per_update`; `unaffected` as cell 3's candidate; churn variant `churn.withdrawn`, `churn.re_announced`, `churn.started_ms`, `churn.sent_ms`, `timing.release_sent_ms`, `timing.resumed_ms`, `timing.last_eor_ms`, `wire.churn_reflected_before_eor` (one count per receiver); the step line `actor.owed_drain_step_longest_ms` |
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
it also checks the churn witness and duplicate count, the gap exclusion and
where it starts, that a plain registry read misses the since-render slice
maximum the harness keeps, the histogram brackets, that a round-trip probe
the RIB never answers ends at its cap as unfinished, and so does a held
read, that the kernel queues counted are only the receivers' connections
(by listening address and port, both ends), that the burst's attributes
are distinct across the full shape, the per-row wire size bounds and rows
per UPDATE, that the mirrored row-credit constants match the RIB's, that
step keys name the family where a histogram carries a `family` label, and
that the byte watch runs only where the gauge is exported and keeps its peak.
`python3 -m unittest discover -s
bench/scale/rrtransport -p 'test_*.py'` seeds each bar's defect into the
analyzer and checks that only that cell changes verdict (owe-whole flips
without spent credit and a restart burst offered as cell 2 are both INVALID;
so are a null owed-drain step instrument, a long poll with no provably long
turn, a dead turn or gauge instrument, a long inbox round trip under a short
poll, an unfinished probe, churn outside the drain or behind every
receiver's End-of-RIB, an over-wide excluded window, a partial move to the
cursor, a candidate release without the step histogram, an unknown step
scope or family label, a release without its `witness` object, a result
without the `row_credit` record, and a held read that is
unavailable, not tight either way, outside the pause, idle or within its
slack, over the wrong connections or with rows not one an UPDATE of one
size; the measured unicast reads with every fourth cursor envelope or
every envelope uncharged FAIL while the measured clean read and a charged
drain short of the credit pass; a unicast run with only `whole` (or
`keyed` and `whole`) steps FAILs, an EVPN run with `cursor` steps, labeled
or not, fails the same way, one with only `whole` steps is report-only
unless `--require-cursor evpn` makes it FAIL, and a byte-credit tree takes
the row witness (an uncharged cursor row FAILs, a clean one passes) while
its byte bound FAILs over the bound and is INVALID without its
`byte_credit` record, uniform rows, a complete byte watch or a dense one;
a FAIL
survives another run's missing instrument or another
repetition's missing or wrong-shape result, and a missing repetition keeps
cell 7 from passing),
removes each required field in turn, and drives the runner with a stand-in binary to check that a
rerun clears stale results.
