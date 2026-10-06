# reloadstall

Deliberate manual performance harness: CI compiles, lints, and unit-tests it, but the measured run is operator-initiated.

Route-server-scale policy-reload UPDATE-stall driver.

## Unsent-data threshold experiment

The experimental Linux socket hook is compiled only with
`rustbgpd-transport/bench-internals`; ordinary daemon builds ignore it. It sets
neither a production default nor a memory cap. `TCP_NOTSENT_LOWAT` controls
unsent queueing and writable notification ([kernel documentation](https://docs.kernel.org/networking/ip-sysctl.html)); socket buffers and bytes already
in flight remain separate costs. The experiment uses the existing coalescing
writer, so a parked writer can retain a private batch as well as shared chunks.

Build in a dedicated worktree, with its own `target`:

```sh
cargo build --release --locked --bin rustbgpd --features rustbgpd-transport/bench-internals
cargo build --profile scale --locked -p reloadstall
```

`bash bench/scale/reloadstall/run-unsent-leg.sh OUT_DIR unset|BYTES [RTT_MS]`
runs the existing matrix's rustbgpd cell with a fresh artifact directory. The
unset arm leaves the socket option alone. A positive `u32` threshold is applied
to every newly connected accepted and outbound BGP writer, including reconnects;
setter/getter failures terminate that writer, and requested/read-back values are
logged once per connection. A raw readback of zero on the unset arm means the
kernel uses its sysctl value. The wrapper records that value before and after
the leg and never writes it. Matrix shape knobs and the canonical cooldown are
preserved, and threshold/RTT/diagnostic inputs are included in provenance.
`experiment.head` and `experiment.diff` record the commit and a binary patch of
staged, unstaged and untracked (non-ignored) changes that applies to it.

A leg passes only when every `session established` event in the daemon log,
reconnects included, follows its own readback for that peer: the requested
value read back on a positive arm, nothing requested and a raw zero on the
unset arm (`check-unsent-readback.py`, result in `readback.exit`). A daemon
built without `rustbgpd-transport/bench-internals` logs no readback, so it
fails either arm instead of silently measuring the kernel default.

The side sampler records `memory.current` before/after each `memory.stat` read,
the kernel's whole-scope `memory.peak`, `anon`/`sock`/other charges, VmHWM, daemon
CPU seconds, and cumulative per-task voluntary/involuntary context switches at
25 ms intervals. It requires a daemon-only scope with swap fenced. A row's
stat fields are near-contemporaneous samples, not an atomic attribution of
`memory.peak`; report the split at the largest sampled current alongside the
kernel peak. Read duration and raced thread counts expose sampling overhead.
Context switches count daemon tasks, not writer future wakeups.

Start with an interleaved unset/64-KiB A/B on the same main-based binary and
harness: three legs per arm, four reloads per leg at 700 peers × 400,400 prefixes.
Report each whole-leg peak and each reload's completion/stall p50, worst observer,
CPU window, and session/parse checks. Do not infer a win from `sock` alone.
Require at least 100 MiB lower whole-cgroup peak, at most 2% regression in
completion/stall p50, and retained tails, CPU/scheduling cost, and session health
before considering a production opt-in. Smaller/larger thresholds are screening
arms, not a substitute for repeated acceptance measurements.

Reader qualification arms use `RELOADSTALL_READER_COUNT` (the first non-churner
changed peers), `RELOADSTALL_READER_DELAY_MS`, `RELOADSTALL_READER_BYTES` (1–65536),
and `RELOADSTALL_READER_PAUSE_MS`. Pacing is acknowledged before each reload
trigger. Slow readers retain a delay between chunks; stopped readers start their
finite pause at the first base UPDATE carrying that round's generation marker,
before recording it or reading more output. Old-generation traffic and compile
time do not consume the pause. A stopped-reader round fails if any selected reader
does not activate its pause. Readers then resume so recovery is checked. Every
observer must still complete, sessions and decode checks still hold, and separate
`healthy_completion_s`/`healthy_maxgap_ms` lines report the unpaced survivors.
For example, repeat both arms with 50 readers at 4 KiB per 5 ms, then with a
5-second stopped-reader interval. These are separate qualification shapes.

An RTT argument runs both loopback endpoints in a disposable user/network
namespace. Where unprivileged namespaces are unavailable, add `--container`:

```sh
docker build -f bench/scale/reloadstall/Dockerfile.runtime -t unsent-runtime .
UNSENT_CONTAINER_IMAGE=unsent-runtime \
    bash bench/scale/reloadstall/run-unsent-leg.sh OUT_DIR unset 20 --container
```

Build the tools image before starting a leg. Its pinned Ubuntu base supports
binaries built against glibc 2.39; use `--build-arg BASE=...` with an appropriate
pinned image for other build hosts. The wrapper resolves the runtime tag to an
immutable image ID, records its inspection, and mounts the separately built,
hashed daemon and harness binaries. It does not compile or pull images during
the measured leg.

The daemon runs directly as PID 1 in a `--network none` container. A second
container shares its network and PID namespaces, so the existing receiver can
SIGHUP PID 1, replace the policy file, and scrape loopback metrics. Tools and
receivers stay in that second container's cgroup; no `docker exec` processes
enter the daemon cgroup. The daemon runs as the invoking host UID without
capabilities. The receiver adds `NET_ADMIN`, `KILL`, `DAC_OVERRIDE` and `FOWNER` to an empty
capability set; the last lets the unchanged receiver preserve policy-file
permissions when copying a generation owned by the daemon UID. Both containers have equal memory and memory-swap limits
(default 100 GiB, override `UNSENT_CONTAINER_MEMORY_BYTES`), disabling swap.

The sampler labels this memory boundary `container-daemon-only`. Its ownership
receipt pins the full container ID, image ID, host PID, PID start time, binary
inode and exact cgroup. It rejects a different image/binary, shared or populated
child cgroups, changed ownership, mismatched memory caps or nonzero swap limit.
Native legs retain their daemon-only systemd scope and process-group checks.
Receivers stop before the daemon. Logs, exits and OOM state are retained before
removal. The `daemon-memory.pre-stop.*` files capture the whole-cgroup high-water
mark, statistics and events **before daemon shutdown**; they are not a final
lifetime peak. The fast trace continues through shutdown until the process exits,
retaining later observed peaks when available. Cleanup bounds TERM then KILL, including
interruptions and failed starts, and only removes this invocation's containers.

Both RTT modes use `receiver-netem.py`: observer TCP (`127.0.0.1` ↔
`127.1.0.0/16`) is redirected from loopback **ingress** into an IFB queue with
half the requested RTT as each direction's delay. Loopback metric scrapes are
unshaped. Receiver ingress avoids the TCP Small Queues interaction documented
by [netem](https://www.man7.org/linux/man-pages/man8/netem.8.html#LIMITATIONS);
[tc-mirred](https://www.man7.org/linux/man-pages/man8/tc-mirred.8.html#EXAMPLES)
describes the IFB redirect. The helper refuses the host namespace, retains queue
and filter JSON plus live observer `ss` TCP RTT samples at one-second intervals,
and fails on missing/mismatched delay, inactive filters, queue/filter drops, or
absent RTT evidence. A successful capability setup alone is insufficient.
The namespace disappears with its owned processes; no host links, routes,
sysctls, modules, bridges or published ports are changed.

The container mode supports the existing IPv4 reload workload and reader pacing,
including mixed changed peers. Dual-stack, membership churn, flapstorm and host
CLI probes are rejected. External file and command options (`RELOADSTALL_OVERLAP_FILE`,
`RELOADSTALL_EVIDENCE_DIR`, `RELOADSTALL_PRE_CHURN_EVIDENCE_DIR`,
`RELOADSTALL_RECEIVED_VIEW_FILE` and `RELOADSTALL_STAGE_CMD`) are rejected before
startup, including empty values; their host paths are not mounted into the receiver.
The driver supplies the loopback reload-metrics address only when `RELOADS` is
positive, ignoring an inherited address in container mode. The matrix host mutex,
two quiet-host samples and full 300-second cooldown still apply. The source patch,
tool/binary hashes, image ID, workload inputs, per-establishment socket readback
and harness status remain required evidence. For a functional check, run both
`unset` and `65536` with
`N_PEERS=12 TOTAL_PREFIXES=1200 RELOADS=2`, 20 ms RTT and slow/stopped readers.
A passing smoke validates the driver; it does not qualify the 700-peer timing or
memory gates. Test both reader qualification shapes at scale before shipping a
setting.

`RUSTBGPD_BENCH_WRITER_POLLS=1` enables per-write poll/pending-poll diagnostic
logs with epoch markers, including failed/canceled attempts but excluding any
teardown linger. They are future poll/resume counts, not actual kernel wakeups.
These logs and their clock reads perturb the burst: keep them off for acceptance
timings and run matched diagnostic arms separately. A smoke only validates the
hook, accounting, and controls. No production setting is approved by this harness.

## What it measures

`N` real BGP stub clients dial a running rustbgpd route server over loopback
TCP (real OPEN/KEEPALIVE/UPDATE wire exchange), announce a full table, run
steady churn from a subset of members, then the driver copies successive
`.rpol` generations over the daemon's live policy file and SIGHUPs it. It
records every observer's inter-UPDATE gaps and post-SIGHUP re-advertisement
completion, so it can answer: how long do UPDATEs stall while the route server
reloads policy under churn, at the receiver. It supports both the historical
all-peer import+export change and a mixed export-only change where only a prefix
of the peer fleet should receive a new export generation.

Stubs bind distinct `127.1.x.y` source addresses with router-ids `240.1.x.y`
(higher than the daemon's, so the inbound connection wins RFC 6286 collision
resolution), use a non-loopback synthetic NEXT_HOP (a `127/8` NEXT_HOP is
rejected with UPDATE error subcode 8; route-server mode passes it through), and
answer ROUTE_REFRESH by re-sending their base slice. It reports per-observer
max-gap / completion percentiles, samples delivered communities to verify which
policy generation is live, and reads daemon RSS from `/proc/<pid>`. In mixed
mode, completion is measured only for changed observers, while max-gap and
session-health checks still cover the full fleet. After every changed observer
has completed the new generation, the harness resets its evidence threshold;
every stable observer must then receive a fresh announced UPDATE carrying the
`stable-out` community marker. Steady churn supplies that independent proof. A
reload is rejected before its CSV row if any session is down, post-completion
stable-marker evidence is missing, or a daemon UPDATE fails to decode. Each
valid reload emits a `reloadstall_csv` record for durable raw receipts.

At successful exit, peers that received a ROUTE-REFRESH also emit one
`route_refresh_accounting` line per family. `received` counts wire requests;
`suppressed` counts requests ignored while that peer/family's replay latch was
pending or its converged-rejoin source replay was blocked; `completed` counts
replays whose final UPDATE was written (or empty
replays); `sent_nlri` counts announced NLRI in replay UPDATEs after successful
socket writes. Counts are cumulative for the whole run, including reconnects;
they are not reset at reload boundaries. The pending latch retains its existing
behavior across reconnects. Existing CSV headers and rows are unchanged.

Native SIGHUP reloads also require a terminal daemon success from
`bgp_sighup_reload_outcomes_total`. Receiver delivery alone can precede a
failed apply acknowledgement and rollback. The driver snapshots the counters
before staging and timing each signal, then checks them while waiting for
receiver completion. A rejected, partial, ignored, or failed outcome aborts
that reload before its CSV row and before the next A/B policy copy. Missing,
decreasing, duplicate, or malformed evidence also fails closed.

The metrics address defaults to `127.0.0.1:9179`, matching the scenario
generators; set `RELOADSTALL_RELOAD_METRICS_ADDR` for another loopback address.
Scrapes have a five-second deadline and run at most once per second while
settlement is pending. This is additional measurement load. Receiver timings
retain their signal/UPDATE timestamps; the `daemon_applied` marker records the
separate settlement check. Older daemons without these counters cannot supply
this proof. Command-driven peer implementations keep their command exit-status
and receiver checks; these are not rustbgpd SIGHUP settlement evidence.

Reload, flapstorm, and `--convergence-only` runs gate initial convergence on
exact unique-prefix bitmap coverage at every observer: the full table minus its
own slice. Duplicate, own-slice, and out-of-range announcements cannot advance
completion. Reload and flapstorm runs disarm the bitmap before the pre-churn
evidence barrier and churn begin; convergence-only keeps it armed through the
ready/ack evidence boundary and rechecks it before exiting. One
`first_exact_bitmap` receipt records the mode and fleet coverage.

After all measurements and any final evidence acknowledgment, successful runs
stop and join churn tasks, send each stub a final Cease, and keep receiving
daemon output until EOF. One 15-second deadline bounds the fleet cleanup.
Read, write, or task failures and cleanup timeouts fail the run; remaining
reader, writer, and refresh tasks are canceled and joined before exit.

Depends only on `crates/wire` (wire encode/decode for the stub sessions).

## Backs

- `docs/perf/reload-stall-2026-07.md` (LAN-333). The full daemon-side scenario
  (700 `[[neighbors]]` route-server-client blocks, `member-in` / `member-out`
  rpol chains, gRPC UDS, and the two policy generations) is pinned there.

## Build and run

Root-workspace member excluded from `default-members`; build it explicitly
with the profiling profile:

```text
cargo build --profile scale --locked -p reloadstall
./target/scale/reloadstall <n_peers> <total_prefixes> <daemon_port> \
    <daemon_pid> <policy_live> <policy_a> <policy_b> <reloads> <control_secs> \
    [changed_peers]
```

The daemon must already be running (load-gated `--release` start) with
`n_peers` route-server-client neighbors and its live policy file at
`<policy_live>`; `<policy_a>` / `<policy_b>` are the two generations copied over
it on alternating reloads.

Set `GEN_RPKI_CACHE=127.0.0.1:3323` when generating a route-server scenario
to add an RTR cache and a reject-invalid term to every member's shared import
chain in both policy generations. A bracketed numeric IPv6 cache address such
as `[::1]:3323` also works. The cache must be started separately; this knob
does not produce VRPs, inject deltas, or hold sessions for measurement.
It is unavailable in the policy-free `GEN_IBGP_RR_ASN` scenario. With the
knob absent, the historical generated files are unchanged.

## Allocator

The harness links jemalloc as its global allocator, the same allocator the
daemon uses. Hundreds of stub readers on a 24-worker runtime grow their frame
buffers and NLRI vectors at the same instant when the daemon delivers a
coalesced post-reload burst; under glibc malloc those reallocations contended
on the arena lock, and the resulting futex wait made the completion median
bimodal from one process start to the next while the daemon sat idle on the
receivers' TCP windows. Receiver-bound receipts taken before this change
(glibc malloc) are not directly comparable on completion time.

## Arg contract

From `src/main.rs` (fewer than 9 positional args prints the usage string and
exits 2):

```text
reloadstall <n_peers> <total_prefixes> <daemon_port> <daemon_pid> \
    <policy_live> <policy_a> <policy_b> <reloads> <control_secs> \
    [changed_peers] [reload_cmd] [--flapstorm K [--flap-rounds N]]
    [--convergence-only] [--no-churn]
    [--converged-rejoin]
```

- `n_peers` — stub sessions to establish (`total_prefixes` must divide evenly).
- `total_prefixes` — base-table size; each stub owns `total/n_peers` /24s.
- `daemon_port` / `daemon_pid` — the running daemon's listen port and PID (PID
  is used for SIGHUP and RSS sampling).
- `policy_live` — the daemon's live `.rpol` file (copied over each reload).
- `policy_a` / `policy_b` — the two policy generations (alternated per reload).
- `reloads` — number of SIGHUP reload cycles.
- `control_secs` — quiet control-window length (baseline inter-UPDATE gap). With
  `--no-churn`, hold the established sessions for this finite window without
  starting churn tasks or their warmup. This requires `reloads=0`, a positive
  `control_secs` and daemon PID, and no flapstorm, reload command,
  `--convergence-only`, or iBGP-RR mode. The final session/decode checks, optional
  evidence acknowledgment, bounded cleanup, and refresh accounting still run.
  Empty inter-UPDATE gap samples in this mode are not performance evidence.
- `changed_peers` — optional number of leading observers whose effective export
  chain changes. Completion waits only for these observers; all-observer gap and
  session checks still include every peer. Omit it for the historical all-peer
  import+export scenario.
- `reload_cmd` — optional (IXP matrix, LAN-334): each reload runs
  `sh -c <reload_cmd>` (e.g. `docker exec <c> birdc configure`) instead of
  SIGHUP-ing `daemon_pid`; a nonzero exit fails the run like a failed SIGHUP.
  The policy-file copy still happens first, so for BIRD/OpenBGPD the "policy"
  files are the generation include/rule files.
- `--flapstorm K` — optional flag (anywhere in argv): alternative mode
  replacing the reload loop. After convergence + the control window, the first
  `K` stubs (never the churners) are closed simultaneously; every survivor
  timestamps receipt of all `K` slices' withdrawals, the `K` reconnect after
  10 s and re-announce, and survivors timestamp re-announce completion.
  Each flapped peer also prints `rejoin_complete_s` from its successful OPEN
  write to the first instant it has both received its first IPv4 End-of-RIB
  and currently holds every expected base prefix (the full table minus its
  own slice and any overlap extras); withdrawals clear coverage until a fresh
  announcement. `eor_before_full_table=true` identifies an EoR that preceded
  the last required route. Missing EoR or incomplete coverage fails the run
  by default. The matrix's OpenBGPD cells use `--rejoin-coverage-only` because
  OpenBGPD sends no EoR to these non-GR stubs: their rejoin time ends at exact
  coverage, and absent EoR prints `eor_before_full_table=absent eor=absent`. An observed EoR prints `eor=present`; no EoR time
  is fabricated. rustbgpd and BIRD cells retain the EoR requirement. Each round prints
  rejoin p50/max alongside the existing survivor percentiles and unchanged
  `flapstorm_csv` records. The rounds still reconnect and re-announce
  without GR retention, so rejoin time can include other flapped peers'
  return and re-announcement. It cannot alone attribute delay to serialized
  initial-table joins.
- `--rejoin-coverage-only` — complete rejoin on exact current table coverage
  without requiring EoR. Valid only with `--flapstorm`; incomplete coverage
  still fails the run.
- `--flap-rounds N` — flapstorm round count, `1..=100` (default 3, the
  historical receipt shape). Valid only with `--flapstorm`.
- `--converged-rejoin` — opt-in rustbgpd GR-helper qualification with
  `--flapstorm K`. Generate its matching scenario with
  `GEN_CONVERGED_REJOIN=1`. It requires zero reloads, the disjoint all-peer
  IPv4 route-server shape, and EoR completion. Other flapstorm instruments,
  overlap, filtering (including `GEN_RPKI_CACHE`), mixed export policies,
  iBGP-RR, and coverage-only completion are rejected. The historical flapstorm mode and CSV stay intact.
  `RELOADSTALL_REJOIN_METRICS_ADDR` selects the loopback metrics/readiness
  endpoint, default `127.0.0.1:9179`.

  Initial OPENs advertise IPv4 GR with R=0; reconnects set R=1 and F=1.
  The fixture declares retained control-plane input, with a 180-second
  disconnected retention cap and 360-second post-reconnect EoR window.
  It makes no forwarding-survival claim. Every round closes K sockets,
  holds them down for 10 seconds, and requires each disconnected peer's
  helper-active flag and exact stale-source-prefix count. Two surviving
  observers with disjoint own slices then request fresh snapshots; both
  must receive EoR and exact table-minus-own coverage. Together these
  snapshots cover the whole retained table. Retention is checked again
  immediately before reconnect.

  No reconnecting source reannounces until **every** joiner has completed
  its successful-OPEN → first-EoR-and-exact-table measurement. Only then
  is current coverage checked again before the first replay message, so
  a latched completion cannot conceal a lost key. Incoming ROUTE-REFRESH
  requests for reconnecting sources are counted and suppressed until this
  guarded boundary opens the whole cohort; initial and survivor refresh
  responders remain active. Source slices and their
  EoRs are then sent to settle GR, followed by fresh
  survivor snapshots and current joiner-coverage checks. Survivor session
  loss, any new base-prefix withdrawal, decode errors, or incomplete GR
  settlement fail the run. `/readyz` is sampled once per second throughout
  each round; non-200 responses and responses beyond 250 ms fail before
  the round's receipt. These probes and the snapshot proofs add load.

  Per-peer `rejoin_complete_s` lines retain the existing EoR-order signal.
  `converged_table_checkpoint` records disconnected and settled proofs;
  `converged_rejoin_csv` records round, fleet size, K, prefixes, rejoin
  p50/max, survivor maximum inter-UPDATE gap during reconnect, readiness
  sample count, RSS, sessions, and decode errors. Survivor gap measures
  continuing churn; unchanged retained routes need no reannouncement.
  A small functional run qualifies the harness, not K=1/K=50 performance.
  That comparison and its optimization decision require a quiet host.

  Example, after separately starting the daemon from the generated config:

  ```text
  GEN_CONVERGED_REJOIN=1 python3 bench/scale/reloadstall/gen-scenario.py 12 /tmp/rejoin 1790
  ./target/scale/reloadstall 12 240 1790 <daemon_pid> \
      /tmp/rejoin/member.rpol /tmp/rejoin/gen-a.rpol /tmp/rejoin/gen-b.rpol \
      0 1 --flapstorm 2 --flap-rounds 1 --converged-rejoin
  ```
- `RELOADSTALL_HEAP_METRICS_ADDR` — optional, valid only with `--flapstorm`;
  a loopback socket address with a nonzero port for the daemon's Prometheus
  endpoint. After each round's `rss_mib` sample the harness scrapes it and
  prints `flap N heap allocated_mib=A active_mib=B resident_mib=C
  mapped_mib=D` from the `jemalloc_*_bytes` gauges (whole MiB), so a post-round
  RSS change can be split between live heap (`allocated`) and allocator
  retention (`resident` minus `allocated`). A gauge the daemon does not export
  prints `absent`, never 0; a failed scrape fails the run. The IXP matrix sets
  it for rustbgpd flapstorm cells.
- `RELOADSTALL_SESSION_NOTIFICATION_METRICS_ADDR` — optional B2 receipt seam,
  valid only with `--flapstorm`. It must be a loopback socket address with a
  nonzero port. The exact 700-peer/400400-prefix/50-flap shape polls the
  daemon's Prometheus endpoint at 1 + 3 × rounds phase boundaries (ten at
  the default three rounds) and emits
  `session_notification_receipt` rows after the notification population has
  reached zero. This proves dequeue accounting only: the monotonic lifetime
  high-water value is not a per-round peak, capacity, latency, or bound.
- `RELOADSTALL_OVERLAP_FILE` with `--flapstorm` — the failover shape. The
  file (from `gen-failover-overlap.py`) gives part of each flapped member's
  slice an alternate announced by a surviving member. The harness announces
  those extras with the stub's ASN prepended, so they lose the initial
  tie-break and become best only when the flapped member closes. The
  withdraw phase then counts each flapped prefix on the alternate's
  announcement, or on a withdrawal at the alternate itself and for prefixes
  without one. Before the first close the run fails unless every alternate
  covers the flapped cohort, no alternate is a churner, each alternate
  currently holds its owner's path, i.e. it lost the initial tie-break. Each round prints a
  `flapstorm_failover_csv` row: daemon CPU-seconds from `/proc/<pid>/stat`
  between the close and the harness's detection of the last survivor's
  completion (a 100 ms poll), survivor completion p50/max, the window's wall
  length, and the daemon's churn-only CPU rate sampled over 2 s just before
  the close. The window also contains that background churn. With
  `RELOADSTALL_FAILOVER_METRICS_ADDR` (the daemon's Prometheus address), the
  row also carries the `distribute_flush` actor-work sum and count between a
  metrics scrape just before the opening CPU read and one just after the
  closing CPU read (`scrape_bracketed_flush_*`: the CPU window plus both
  scrapes). `failover_cell.sh` runs one such cell end to end; a daemon
  built with `--features rustbgpd-rib/bench-internals` additionally logs
  which grouped members took the shared payload or the per-member walk in
  each mixed pass, and the script totals them. First receipt:
  [failover alternates cell](../../../docs/perf/failover-alternates-2026-09.md).
- `--convergence-only` — fail-closed capture mode. It requires `reloads=0`, `control_secs=0`, no flapstorm or
  reload command, an empty `RELOADSTALL_EVIDENCE_DIR`, and no `RELOADSTALL_PRE_CHURN_EVIDENCE_DIR`.
  It verifies exact table-minus-own-slice coverage, healthy sessions, and zero parse errors; signals `ready`;
  waits up to 15 seconds for `ack`; rechecks; emits `convergence_only_receipt`; and exits before churn work.

`daemon_pid` may be `0` when an outer sampler owns RSS measurement (RSS
columns report 0); that requires `reload_cmd`, `--flapstorm`, or `--convergence-only`. The
9/10-positional-arg SIGHUP invocation above is a frozen contract and behaves
exactly as before.

### Soak extensions (env vars, all additive)

Every knob absent reproduces the frozen one-shot contract exactly. The
route-server flagship soak (`tests/soak/run-soak-rs-flagship.sh`) sets them to
turn the fixed reload sequence into a self-paced long window with periodic
max-prefix trip cycles:

- `RELOADSTALL_CYCLE_QUIESCE_SECS` — inter-reload quiesce in seconds
  (default 20, the historical value). The soak sets this to its reload
  interval, so `reloads × interval` paces the whole window.
- `RELOADSTALL_TRIP_EVERY` — after every K-th reload cycle, run one
  max-prefix trip cycle on the designated member, stub 0 (0/absent = never).
  Requires the SIGHUP reload mode with `changed_peers == n_peers`, no
  overlap file, and `n_peers > 8` (stub 0 must not be a churner). A trip
  cycle: disarm generation markers → arm survivors' withdraw bitmap over
  stub 0's slice → announce `RELOADSTALL_TRIP_PREFIXES` prefixes over the
  daemon's configured `max_prefixes` bound → wait for the Cease teardown →
  verify withdraw propagation at every survivor → arm the announce bitmap →
  reconnect-retry through the hold-down until the daemon's one timed
  restart admits the session → re-announce only the compliant base slice →
  verify re-announce propagation → integrity check (all sessions up, zero
  parse errors). Each phase prints a `trip N <phase> wall_us=…` marker and
  each cycle emits one `trip_csv` record
  (`trip_csv_header,trip,peers_total,teardown_s,withdraw_s,holddown_s,reannounce_s,rss_mib,sessions_up,parse_errors`).
- `RELOADSTALL_TRIP_PREFIXES` — over-limit block size (default 64), drawn
  from base indexes `[total, total + K)`: outside every observer's
  completion bitmap and the churn space, but shaped like base routes for
  the daemon's import path and session accounting.
- `RELOADSTALL_TRIP_REESTABLISH_SECS` — teardown-to-re-established deadline
  (default 300); must exceed the daemon-side `max_prefix_restart_seconds`.
- `RELOADSTALL_FINAL_QUIESCE_SECS` — post-run session hold in seconds
  (default: the cycle quiesce), applied only when the LAST reload carries a
  trip cycle: the engine sleeps with every stub session still up after
  `trip N complete`, so an outer runner can drain the trip's daemon-side
  evidence (`bgp_max_prefix_usage`/`limit`/`headroom`) from live metrics
  before teardown. Never applies to the one-shot contract (no trips).

`gen-scenario.py` grows a matching additive pair: setting both
`GEN_TRIP_MAX_PREFIXES` and `GEN_TRIP_RESTART_SECONDS` adds
`max_prefixes` / `max_prefix_restart_seconds` to neighbor 0; absent, the
emitted config is byte-for-byte the historical one.

### iBGP-RR extensions (env vars, all additive)

The route-reflector flagship soak (`tests/soak/run-soak-rr-flagship.sh`)
switches the stubs to iBGP route-reflector-client mode. Both knobs
absent reproduces the frozen eBGP route-server contract exactly:

- `RELOADSTALL_IBGP_RR_ASN` — 1..=65535: every stub OPENs with this
  shared local AS (the daemon's ASN, so it must be u16-representable),
  announces with an EMPTY `AS_PATH` plus `LOCAL_PREF 100` (real-world
  iBGP origination), and initial convergence gates on the exact
  per-observer bitmap. Requires the zero-reload shape: `reloads = 0`,
  no flapstorm / reload command / convergence-only, no overlap or
  evidence files, no trip cycles, all-peer `changed_peers`.
- `RELOADSTALL_IBGP_RR_HOLD_SECS` — after the control window, hold the
  fleet under the steady churn for this long (one fail-closed
  `rr_hold elapsed_s=… churn_cycles=… sessions_up=… rss_mib=…` status
  line per minute; any session drop or decode error aborts), with
  per-UPDATE event recording disabled to bound 24 h memory. Then the
  terminal reflected-delivery verification runs: every stub sends a
  Normal ROUTE_REFRESH, the daemon re-sends its Adj-RIB-Out, and every
  observer must complete its full-table-minus-own-slice bitmap exactly
  (min == max == expected across the fleet), emitting one
  `rr_terminal_receipt,peers=…,prefixes=…,per_peer=…,expected=…,min_unique=…,max_unique=…,sessions_up=…,parse_errors=…,churn_cycles=…`
  record. Requires `RELOADSTALL_IBGP_RR_ASN`.

`gen-scenario.py` grows the matching additive knob: `GEN_IBGP_RR_ASN`
emits the iBGP route-reflector scenario (`asn = <value>`,
`cluster_id = "10.0.0.1"`, every neighbor `remote_asn = <value>` +
`route_reflector_client = true`, and no `[policy]` section — iBGP is
outside RFC 8212's default-deny and the RR soak runs zero reloads; the
`.rpol` files are still written to satisfy the harness's positional arg
contract). Mutually exclusive with the `GEN_TRIP_*` knobs; absent, the
emitted config is byte-for-byte the historical one.

### Small-UPDATE packing (env vars, all additive)

Absent, every stub packs 900 IPv4 NLRI per announce UPDATE, the frozen
contract.

- `RELOADSTALL_NLRI_PER_MSG=k` (1..=900) — announce UPDATEs carry at most
  `k` NLRI, and each UPDATE of a stub carries its own MED so the daemon cannot
  pack them back into fewer outbound UPDATEs. Applies to the base announce,
  `ROUTE_REFRESH` re-sends and flapstorm re-announcement; churn keeps its
  one-UPDATE 16-prefix flap.
- `RELOADSTALL_NLRI_PER_MSG_STUBS=K` — apply the packing only to the first
  `K` stubs (default: every stub). With `--flapstorm K`, exactly the flapped
  members announce in small UPDATEs, so the cell compares their
  re-announcement against the packed default at an equal prefix count.

### Dual-stack and filtering extensions (env vars, all additive)

Both knobs absent reproduces the frozen IPv4-only contract and the
generator's historical output byte for byte.

- `RELOADSTALL_DUALSTACK=1` — every stub negotiates `ipv4_unicast` **and**
  `ipv6_unicast` on its one IPv4-transport session. The daemon's OPEN must
  carry both multiprotocol capabilities, or establishment fails (an
  un-negotiated family is never reported as delivered). `<total_prefixes>`
  becomes the **total across both families**, split evenly by default. Set
  `RELOADSTALL_IPV4_PREFIXES=N` for an exact IPv4 inventory; IPv6 receives
  `total - N`. Each family is divided into contiguous slices: every member
  receives `family_total / n_peers` prefixes, and the first
  `family_total % n_peers` members receive one extra. Every member must have
  at least one prefix in each family. IPv4 /24s use body NLRI and IPv6 /48s
  (`3001:HHHH:LLLL::/48`) use `MP_REACH_NLRI` with a
  synthetic `fd09::x:y` next hop; churners flap one 16-prefix block per
  family (`3002:c:j::/48` for IPv6). Every observer keeps an independent
  per-family unique-prefix bitmap: initial convergence, reload completion,
  and post-completion stable-marker evidence each require **both** families
  at every observer, and the historical `completion` of an observer is its
  slower family. A second `first_exact_bitmap6` receipt and a
  `reloadstall_dualstack_csv` row per reload (per-family completion,
  leading stall, family-restricted max-gap, withdrawal accounting, and
  per-family stable-marker counts, explicit IPv4/IPv6 totals) are printed after the historical lines,
  which keep their format (`prefixes` is the total). Requires the reload
  mode: no flapstorm, trips, iBGP-RR, overlap, received-view, or
  `--convergence-only`.
- `RELOADSTALL_FILTER_COUNT=K` — filtering policy shape, paired with the
  generator's `GEN_FILTER_COUNT=K`. Generation B rejects base indexes
  `0..K` of every family (the head of member 0's slice) at the changed
  observers; generation A permits them again. Completion of a B reload
  additionally requires a withdrawal of every named prefix at every changed
  observer other than member 0. A named prefix delivered **with** the marker
  (`filtered_leaked`), a withdrawal of any other base prefix at a changed
  observer (`bystander_withdrawn`), or any base withdrawal at a stable
  observer (`stable_withdrawn`) fails the reload; duplicate named
  withdrawals are counted and published. Works with or without dual-stack.

For 700 members and 400,400 total routes, `RELOADSTALL_IPV4_PREFIXES=360360`
selects exactly 90/10: 360,360 IPv4 and 40,040 IPv6. Members 0–559 own
515 IPv4 prefixes and the rest own 514; members 0–139 own 58 IPv6 prefixes
and the rest own 57. The filtering count must fit member 0 in **both**
families (at most 58 for this shape; the historical equal-family count of
64 does not fit). Omitting the count selects 50/50, or specify
`RELOADSTALL_IPV4_PREFIXES=200200` explicitly. Odd totals require an explicit
IPv4 count. The IPv4 count knob is rejected without dual-stack mode.
Use a fresh `ARTIFACTS_DIR` for each mix and policy shape. The matrix runner
compares effective workload inputs before resuming a passing cell; changed or
missing input identity fails closed. Historical receipts remain verifiable
offline, but cannot be resumed without that identity.

Churn tasks start before the control window and remain active throughout
all reloads. Each dual-stack reload prints `reloadstall_churn_overlap`:
per-family successful socket-write counts and first/last monotonic timestamps
inside the trigger-to-last-changed-observer-completion window. Only the dedicated
churn blocks count; base announcements, refresh replies, channel enqueues,
and writes after completion do not. `overlap_observed=false` reports a window
with no write in one or both families; it does not change route-correctness
acceptance or extend completion. A concurrent-churn campaign must require
`overlap_observed=true` for each reload as a separate proof gate. Socket writes
show sender progress; receiver inventory and stable-marker checks remain the
independent delivery proof.

The existing 20-member 50/50 receipt is historical. These inventory options
and overlap rows do not establish asymmetric or 700-member scale proof.

`gen-scenario.py` grows the matching pair: `GEN_DUALSTACK=1` emits
`families = ["ipv4_unicast", "ipv6_unicast"]` on every neighbor, and
`GEN_FILTER_COUNT=K` gives generation B a `prefix-set filtered` (base indexes
`0..K` of each emitted family) rejected by `member-out` before tagging.
`bench/scale/matrix/run-matrix.sh` passes both env pairs through unchanged
and adds `CHANGED_PEERS` (the mixed export-only cohort for the rustbgpd cell)
and `PROBE_PREFIXES` (a 50 ms `rbgp health` loop plus a 250 ms
`rbgp rib --prefix` loop over the listed prefixes, logged per call). The
pinned dual-stack shape lives in
[`docs/perf/artifacts/ixp-dualstack-2026-09/README.md`](../../../docs/perf/artifacts/ixp-dualstack-2026-09/README.md).

Cross-daemon cells generate their route-server configs with
`gen-bird-scenario.py` / `gen-obgpd-scenario.py` (same addressing contract)
and are sequenced by `bench/scale/matrix/run-matrix.sh`. The runner defaults
to the frozen `historical` comparator generation (BIRD 3.3.1 / OpenBGPD 9.1).
Set `COMPETITOR_GENERATION=current` to select the explicit current pair:

- BIRD 3.3.3, built as `bird:v3.3.3-m101` from the checksum-pinned
  `tests/interop/Dockerfile.bird-v332` with the
  [current comparator build args](../../../docs/interop.md#pinned-bird-3-images-m43-and-m101);
- OpenBGPD 9.3 at
  `openbgpd/openbgpd@sha256:8f4b44f25796beaecb72ab7f099a3914961ac444a9de094ffca6a4614e741412`.

The pair is not independently overridable. Initial runs record the requested
reference and resolved image ID; resumes require both identities to match.
The generators accept the same optional final `historical` / `current`
selector. The first two version/image header comments are the only generated
config differences; every remaining config line and all policy bytes are
identical.

Generate matching daemon configuration and policy generations with:

```text
python3 gen-scenario.py <n_peers> <out_dir> [listen_port] [changed_peers]
```

When `changed_peers` is supplied, the generator keeps
`member-in` byte-for-byte stable, changes `member-out` between generations for
the leading observers, and assigns the remaining observers a content-stable
`stable-out` chain.

Receipt run shape (heavy — 700 real sessions × 400k routes; do not run casually):

```text
python3 gen-scenario.py 700 <scenario-dir> 1790 600
reloadstall 700 400400 <port> <daemon_pid> <live.rpol> <gen-a.rpol> <gen-b.rpol> 4 30 600
```

## Membership and dataset churn

The opt-in matrix cell keeps the 700 announcing members and their 400,400
dual-family routes, and adds two receive-only members. Each of four reloads
replaces that pair with two new addresses and ASNs. One member in every pair
uses TCP MD5; every core and rotating member uses GTSM. Each member's import
policy references its own ASN dataset and dual-family prefix dataset. Removed
members' policy files and dataset bindings leave the active configuration.
This exercises membership and binding changes alongside export-policy reloads;
it does not rotate ownership of the announcing fleet's routes.

Build the daemon, CLI, and harness from the source under test. The helper
requires Linux and Python 3.11 or newer (`asyncio.TaskGroup` and `timeout`).
From the repo root, run on an otherwise quiet lab host:

```bash
out=$(mktemp -d /tmp/membership-cell.XXXXXX)
ulimit -n 65536
GEN_DUALSTACK=1 RELOADSTALL_DUALSTACK=1 RELOADSTALL_GTSM=1 \
RELOADSTALL_MEMBERSHIP_CHURN=1 RELOADSTALL_CYCLE_QUIESCE_SECS=20 \
N_PEERS=700 TOTAL_PREFIXES=400400 CHANGED_PEERS=600 RELOADS=4 CONTROL_SECS=30 \
PROBE_PREFIXES='20.0.0.0/24 3001::/48' ARTIFACTS_DIR="$out" \
    bash bench/scale/matrix/run-matrix.sh rustbgpd >"$out/driver.log" 2>&1
printf '%s\n' "$?" >"$out/driver.exit"
python3 bench/scale/reloadstall/check_membership_cell.py \
    "$out" 700 400400 200200 600 0 4 >"$out/qualification.json"
```

Use `N_PEERS=20 TOTAL_PREFIXES=11440 CHANGED_PEERS=16` for preparation, and
pass `20 11440 5720 16 0 4` to the checker. This mode supports an equal family
split and permit-set-preserving export changes. It owns the stage and final
evidence hooks; do not supply other commands for those hooks.

The matrix retains its host mutex, two quiet-host samples, per-family exact
wire inventories, continuous churn overlap, zero-failure health/RIB probes,
and core session/error checks. The membership mode additionally aborts at
16 GiB daemon-tree RSS. Every new pair must establish and receive every unique
base-table prefix in both families, carrying the current generation's export
marker, within 60 seconds of staging. Each stage
checks the exact neighbor and dataset-status rosters, nonempty error-free
datasets, and removal of the old pair's dataset metric series. The checker
requires the generation reload route and zero daemon ERROR records.

Unchanged-member continuity uses paired daemon-side TCP socket inodes and
four-tuples from Linux `/proc/net/tcp`, unchanged API flap counts, and
nondecreasing uptime. The core harness never reconnects these members and
retains its independent session checks. These observations constrain socket
reuse ambiguity; they do not expose or compare the daemon's internal actor
session IDs. Intentional departures are allowed only for the scheduled pair
after its corresponding reload trigger. They cannot exempt a core peer loss.

`membership_churn.py` is the bounded two-receiver helper, not a second scale
driver. `RELOADSTALL_STAGE_RELOAD` gives its stage command the 1-based reload
number; `RELOADSTALL_STAGE_GENERATION` remains `a` or `b`. Scenario receipts
retain the before/after TCP snapshots, loaded dataset status, metric snapshots,
and joining IPv4/IPv6 inventories for replay. Run its focused regressions with:

```bash
python3 -m unittest discover -s bench/scale/reloadstall -p test_membership_churn.py
```

The [September 2026 membership receipt](../../../docs/perf/ixp-membership-churn-2026-09.md) retains a passing 20+2 preparation, a 702-member cell that failed readiness, and the v0.70.0 rejection control.

## Policy-stats reload cell

`policy_stats_cell.sh` measures `GetPolicyStats` through changed-policy
reloads on the isolated-generator placement: the daemon on CPUs 2–3 (two
runtime workers), this harness on CPUs 4–5 and the probes and CPU sampler on
CPUs 8–15. It runs 1,000 peers with 400 IPv4 prefixes each and 12 reloads in
alternating directions. Each reload gets one concurrent `neighbor` and
`policy stats --direction both` pair, fired 0.50 s after the cohort hot-apply
completes so that it starts in the −220 to 0 ms band before the RIB commit. A
quiescent `policy stats --direction both` probe follows 20 s after the reload
completes, inside the 40 s inter-reload quiesce. Nothing is retried.

Build release `rustbgpd` and `rbgp` from the source under test, and
`reloadstall` from the root workspace. On an otherwise quiet host, from the repo
root:

```bash
cargo build --locked --release -p rustbgpd -p rustbgpctl --bin rustbgpd --bin rbgp
cargo build --locked --profile scale -p reloadstall
bash bench/scale/reloadstall/policy_stats_cell.sh target/release \
    target/scale/reloadstall "$(mktemp -d)/run"
```

The run directory keeps the daemon log, every probe row and reply body, the
engine log, metric snapshots, a 1 s CPU sample of the pinned cores and their
SMT siblings, and `environment.json` (source, binary hashes, placement). The
analyzer matches each statistics call to its audit record and writes
`summary.json`: per-stage timing and the import capture detail (publications
read, waits taken) for in-band, all pair and quiescent calls, deadline
misses, reload durations, per-row `policy_generation` values, and the flat
verdict. It exits 0 (PASS) only if every call returns complete rows within 2 s,
at least six complete pairs start in the band, and the in-band maximum of the
summed stage `elapsed_ms` stays within twice the quiescent median plus 50 ms;
a missed criterion exits 1 (FAIL). Every statistics call must match exactly
one audit record with well-formed `export`, `import` (with its capture detail) and
`datasets` stages, or a prefix ending at a failed stage. Otherwise the run
exits 3 (INVALID), and `invalid_calls` names each such call. Run caps scale
with `RELOADS`, `CONTROL_SECS` and `QUIESCE_SECS`.
Re-run the analyzer alone with
`python3 bench/scale/reloadstall/policy_stats_cell.py analyze RUN_DIR`.
Neighbor stale rows are counted, not gated. The CPU sample reports load from
other processes on the daemon's cores; a run with material foreign load is not
comparable. Run the focused checks with:

```bash
python3 -m unittest discover -s bench/scale/reloadstall -p test_policy_stats_cell.py
```
