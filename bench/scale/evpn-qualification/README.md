# EVPN daemon qualification

This runner compares a privately enabled, non-RTC owned EVPN daemon with the
same source using private EVPN output. Production ownership stays disabled.
The candidate export alone calls `with_bench_evpn_group_ownership`; both exports
sample the same bench-only readout at nominal 20 Hz. No configuration, environment or RPC knob
is added to the daemon. The observer is a source fragment, compiled only after
the runner inserts it into its private export.

Commit the reviewed source, then prepare and build a new campaign outside the
checkout. Preparation accepts only a clean source commit; builds verify every
exported source file against that commit's archive plus the reviewed constructor
and observer patches. Candidate and control use independent Cargo targets.
Builds inherit the launcher's CPU affinity; use `taskset` on the build command
to restrict its cores.

```sh
python3 bench/scale/evpn-qualification/qualify.py prepare /tmp/evpn-memory
python3 bench/scale/evpn-qualification/qualify.py build /tmp/evpn-memory
bash bench/scale/evpn-qualification/run.sh /tmp/evpn-memory --correctness-only
```

The correctness smoke uses three clients with ten routes each and suppresses
measurement fields in its result. It requires actual owned candidate routes,
an empty candidate private EVPN body store, an exact private control body count,
exact receiver key sets, zero executed provenance resets across all five causes,
and a daemon-only cgroup with `memory.swap.max=0`. Release builds retain the
default jemalloc allocator; the live-heap metric must exist. The driver runs
outside the daemon cgroup. Readiness samples and finish-handshake errors are
retained. The smoke is not a performance receipt.

Use a separate prepared campaign for measured runs, with explicit UTC
`--window-start` and `--window-end` ISO-8601 arguments to `prepare`. There is no
default timed interval. The runner takes the canonical host lock. Before every
measured cell it checks the frozen interval, passes the existing quiet-host
gate, and checks the interval again immediately before launching the daemon.
The end is a last-start cutoff: an admitted cell keeps its normal bounded
operation and cleanup deadlines, and no later cell starts outside the interval.
Omit `--correctness-only` only for that authorized campaign. It installs no timer and must be serialized
with other qualification work. Each shape has three samples per arm in strict
candidate/private alternation, with 45 seconds of settling after exact initial
convergence and before the finish acknowledgement:

| Fixed route total | Smaller fleet | Larger fleet |
| --- | --- | --- |
| 37,500 | 75 clients × 500 routes | 150 × 250 |
| 100,000 | 100 clients × 1,000 routes | 200 × 500 |

Every client originates 80% Type 2 and 20% Type 5 routes and receives every
other client's routes. The raw live-heap slope must be at most **10 bytes per
route per additional receiver in each pair**, including all per-member residue.
There is no post-hoc baseline subtraction. Cgroup peak and settled slopes are
reported separately; neither substitutes for live heap. The summary also
reports bytes per additional receiver, while each cell retains actual owned
and private route counts, per-peer retained/peak provenance, metadata residue,
budgets and all five executed-reset counters. The historical memory result is
not an input to the verdict.

```sh
bash bench/scale/evpn-qualification/run.sh /tmp/evpn-memory-measured
python3 bench/scale/evpn-qualification/qualify.py analyze /tmp/evpn-memory-measured
python3 -m unittest discover -s bench/scale/evpn-qualification -p 'test_*.py'
```

Preserve failed campaigns. `result.json` identifies PASS, FAIL or INVALID and
retains the error; build logs and exit codes survive a failed build. The final
consumer rereads raw metrics, driver output and daemon ownership observations.
Missing arms, missing repetitions, changed bars, identical binaries, private
candidate ownership and nonzero reset counters cannot be accepted.
An acceptance-bar miss in the private control is retained as FAIL baseline
evidence while later scheduled cells continue. The aggregate remains FAIL and
lists failed cells; it does not claim a qualified comparison. Candidate misses,
technical INVALID results and cleanup failures still stop the runner. Readiness
samples retain `http_error_code` separately from a transport-failure status of 0.

The memory summary covers **initial-load memory only**. The separate recovery
runner requires a new campaign, using the same preparation and build commands:

```sh
bash bench/scale/evpn-qualification/run.sh --recovery /tmp/evpn-recovery --correctness-only
# In the agreed quiet window, on a separate prepared campaign:
bash bench/scale/evpn-qualification/run.sh --recovery /tmp/evpn-recovery-measured
python3 bench/scale/evpn-qualification/recovery.py analyze /tmp/evpn-recovery-measured
```

Recovery uses two export policies with different delivered communities. Both
groups must actually exist before traffic; policy names alone are insufficient.
The measured shape has 150 clients and 37,500 routes. Two clients remain as
anchors; the other 148 move to the existing second group and back. The smaller
functional exercise uses three clients and 30,000 routes and reports no timing
verdict. Its route count must fill the real 4,096-message transport writer queue
within the same fixed churn sequence; smaller inventories can remain fully queued.
Neither shape exercises a missing destination group or moves every peer.

The controller pauses actual socket readers with acknowledged generation fences,
then issues 32 fixed full-window churn rounds. Both arms must show all members
dirty together in two consecutive actual observations at 20 Hz: 150/150 in each
measured observation. Two isolated 150/150 observations separated by 149/150 do
not pass. The observer captures timestamps before building each receipt and
emits at most once per anchored 50,000 µs slot, skipping missed slots without
catch-up or interpolation. Both online and final checks require adjacent raw
records in adjacent slots with an actual timestamp gap greater than zero and
at most 50,000 µs; there is no extra tolerance. Queue occupancy and a pause
acknowledgement do not establish that condition. A real Route Refresh
must leave an outstanding refresh/EoR obligation, observed before, during and
after another paced source-update sequence. The private observer retains three
origins separately: pending EVPN refresh response, pending EVPN EoR, and
completion-receipt owed-marker bits. Their union counts each active outbound
peer once. The existing `marker_debt` field still means completion-only debt;
the common union does not prove that a complete feed was already admitted.
The fixed sequence drains each source's writes and
waits 50 ms before issuing the next source's updates in both arms. Driver-side
timestamps bound the sequence; Python's later acknowledgement time is not its
completion timestamp. The pacing gaps do not prove a continuous socket write
in flight. Missing protocol obligation fails the exercise; no synthetic hold or RTC state
is inserted. Every writer acknowledgement follows the socket write, not queue
admission. Socket writes alone are not an applied-input barrier: each source
also sends an ordered EVPN EoR after the burst. An identical private observer
in both exports logs it after the real RIB handler. Every source must reach
the new barrier generation with no pending route batches, distribution window
or withdrawal retirement before the runner proceeds. This prevents a wrapped
route window from looking converged while later input is still queued. Raw
receiver UPDATE captures are limited to 128 MiB per receiver.

The fixed recovery bars are:

| Gate | Requirement |
| --- | --- |
| Readiness | Requests scheduled at 20 Hz in every phase; zero errors or non-200 responses; every measured latency below 200 ms |
| Wire convergence | Each regroup and recovery at most 60 seconds; candidate median at most private median × 1.03 across three alternating samples |
| Timing origin | Regroup starts at SIGHUP; recovery starts after every socket resume acknowledgement |
| Provenance headroom | Observed peer and daemon peaks at most 80% of the existing 16 MiB / 256 MiB budgets |
| Settlement | No dirty members, live recovery obligations, pending refresh/EoR, completion marker debt, completion receipts or pending resets; all five executed-reset counters remain zero |

The 900-second initial-load bound is a safety timeout. Normal daemon reload and
RPC deadlines remain unchanged. Charged metadata after settlement is reported;
it is not forced to zero or subtracted from memory slopes. Raw phase events,
probe samples, daemon observations and captures remain available on failure.
Recovery completion includes the requested EoR reaching every receiver, as
well as the exact route inventory; marker enqueue at the RIB is insufficient.

The independent wire checker validates every Type 2/5 identity, non-key
announcement field, next hop, prepared attribute and withdrawal. A transient
bad attribute or an unknown/duplicate withdrawal cannot be hidden by a later
correct state. Clean policy changes also reject a per-key new/old/new rollback
in either transition direction. Initial and clean-regroup phases compare ordered per-key event
streams between arms. A separate quiescent refresh requires complete replay
coverage before EoR. The concurrent recovery phase compares exact final NLRI,
common attribute TLVs and MP next-hop bytes; it permits idempotent replay and
does not claim identical event ordering under recovery.

This bounded matrix does **not** clear all of ADR-0099 section F. Full-fleet
regroup into a new or absent destination, RTC behavior, soak and production
activation remain separate gates. Missing raw evidence, an unobserved phase or
a failed bar cannot be replaced by component tests or a passing memory result.
Terminal-only complete-feed marker retention and repeated complete-feed
producer cost remain unqualified. The recovery summary always records
`terminal_only_qualified: false`; common protocol-obligation coverage does not
replace those gates.
