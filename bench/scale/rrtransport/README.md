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
| report-only | `credit-restart unicast\|evpn` | the cell 2 fixture behind an RFC 4724 restart: selection deferred, 150 private receivers paused for 30 s while the restarting source sends 150,000 routes at once and its End-of-RIB | exact final wire state, End-of-RIB order, session resets, recovery time, the same unaffected receiver; no witness |
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
resume.

The burst is paced because the RIB is serial: sent at once, 150,000 routes
toward 150 private receivers occupy it for tens of seconds on any tree, with
the readers paused or not, and the healthy receiver's churn waits behind them
in the RIB's queue. That delay measures the backlog, not the credit. One
1,024-route UPDATE every 500 ms is about half the rate the RIB stages them,
so the queue stays short and cell 3 shows what spent credit costs a healthy
peer. The pause must stay below the receivers' 90 s hold time: a stub
counts its hold time across a read pause.

**Exhaustion witness.** The cell must show that every burst receiver spent
its ordinary credit. The result records the peak of the credit gauge, summed
over peers: `bgp_rib_outbound_credit_bytes` on a tree that exports it, else
`bgp_rib_outbound_credit_rows`. The analyzer compares that peak with the
number of burst receivers times the tree's per-peer credit at the cell's 153
registered peers (the burst receivers, the healthy one and the two sources):
2 GiB / 153 = 14,035,840 bytes on a byte-credit tree, 16,777,216 / 153 =
109,655 rows on a row-credit tree. Admission stops within one row of a
peer's credit, so a sum at that product means every burst receiver reached
it. A credit refusal on every burst receiver
(`bgp_outbound_commit_refusals_total{reason="outbound_credit"}`) is accepted
too; a clean peer past its credit owes keys instead of refusing, so the full
shapes show none. Without either the cell is INVALID, never PASS, and the
verdict line names what it counted.

Owe-whole flips (`bgp_rib_outbound_owing_flips_total`) are recorded but are
not a witness. An RFC 4724 selection release owes its family whole to every
private receiver by design, one flip per receiver at any table size, and
delivers it as an uncharged whole-table operation: a 4-receiver, 4,096-route
restart burst shows 4 flips with no credit in use. That is why the restart
burst is no longer cell 2. `credit-restart` keeps it as a wire and recovery
check (routes before the held End-of-RIB, nothing after it); `credit_bars.py
check` reads its `restart-<family>.json` and no campaign bar does. A result
whose `shape.trigger` is not `ordinary_announce_burst` is INVALID as cell 2.

The credit-rows, credit-bytes, dirty-peer and live-operation gauges are
sampled by the RIB once per run-loop iteration, so a RIB unit that spans a
whole cell would hide them; the paced burst gives the RIB an iteration per
UPDATE.

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
example to show that cell 2 exhausts credit on a tree. The restart burst is
not in the default cell list; name `restart-unicast` or `restart-evpn` to
run it. A `--pause-ms` or
`--seconds` override on the binary also marks its result correctness-only:
only the fixed shape is a measurement.

One arm's full set takes about 15 minutes of cells plus the quiet-host
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
the fixed 9 probe cells.

| Cell | Bar |
| --- | --- |
| 1 | no OOM; candidate cgroup peak ≤ parent peak − 1.5 GiB; candidate credit-bytes peak ≤ 2 GiB + 150 × one 1,024-row pass |
| 2 | witness on both arms; exact wire state, End-of-RIB order and zero resets in every run; recovery ≤ max(parent × 1.25, parent + 2 s) |
| 3 | no candidate delivery gap over 1 s; candidate p99 ≤ parent p99 × 1.10 |
| 4 | zero dirty episodes in every candidate probe cell |
| 6 | report-only |

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
| 2 | `exhaust-<family>.json`, every run of both arms | `mode`; `shape.receivers`, `shape.rows_per_receiver`, `shape.pause_ms`, `shape.burst_interval_ms`, `shape.trigger`, `shape.registered_peers` fixed; `witness.refused_receivers`, `witness.peak_credit_rows`, `witness.receivers` (and `witness.peak_credit_bytes` on a byte-credit tree); `checks.final_state_exact`, `checks.one_eor_before_burst`, `checks.no_session_resets`; `timing.recovery_ms` once every wire check passed |
| 3 | `exhaust-<family>.json`, every run of both arms | `mode`; `unaffected.injected` and `unaffected.delivered` (nonzero), `unaffected.p99_latency_ms`, `unaffected.max_gap_ms` |
| 4 | `probes.json`, every run of both arms | `mode`; `probes` = the fixed 9 cells (`cell`, `shape`, `peers`, `stall_ms`; restart `table`), each candidate cell with `dirty_episodes` |
| 6 | `fill-<family>.json`, every run of both arms, each family | `mode`; `shape.receivers`, `shape.rows_per_receiver` fixed; candidate `estimate.bytes_per_queued_row` and `row_size_of` |
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
checker; `python3 -m unittest discover -s
bench/scale/rrtransport -p 'test_*.py'` seeds each bar's defect into the
analyzer and checks that only that cell changes verdict (owe-whole flips
without spent credit and a restart burst offered as cell 2 are both INVALID),
removes each required field in turn, and drives the runner with a stand-in binary to check that a
rerun clears stale results.
