# irrreload — IRR-scale reload-receipt matrix

Reload stall + completion under live sessions with a realistic multi-MB
IRR-generated member policy. The full-shape comparison covers rustbgpd's
SIGHUP parse-then-swap path versus BIRD 3.3.x and OpenBGPD 9.x. The streamed
gRPC transactional path runs the same canonical shape as a separate two-root
receipt; its rows never enter the cross-daemon comparison.

This directory is the campaign runner and protocol. The instrument is the
existing `bench/scale/reloadstall` harness — real BGP stub
sessions over loopback TCP, receiver-side timestamps, generation-marker
completion tracking — driven by `bench/scale/reloadstall/gen-irr-scenario.py`,
which can emit every native representation from one seeded dataset.

## What is being reloaded

The IXP operation this models is the routine IRR filter refresh: the daily
regeneration of every member's prefix filters from IRR/PeeringDB data,
pushed into the running route server while sessions stay up. Between the two
policy generations:

- a parameterized fraction of members (default 10%) get ~1% of their filter
  list's padding prefixes replaced — content-real, output-neutral (announced
  prefixes are never touched), forcing a real recompile of multi-thousand-
  entry prefix sets;
- the export marker community swaps (`65400:1000` ⇄ `65400:2000`), forcing
  the full re-advertisement the harness timestamps for completion — the same
  mechanics as `docs/perf/ixp-matrix-2026-07.md` S2.

## Shape (a harness parameter, stated exactly)

| Parameter | Smoke (`SMOKE=1`) | Full cross-daemon | Full transaction |
|---|---|---|---|
| Members (`N_MEMBERS`) | 10 | 320 | 320 |
| Announced base table (`TOTAL_PREFIXES`) | 100 | 183,040 (572/member) | 183,040 (572/member) |
| Per-member IRR filter list (`MIN_LIST`–`MAX_LIST`) | 100 | log-uniform 1,000–40,000 | log-uniform 1,000–40,000 |
| Per-member change probability (`CHANGED_FRACTION`) | 10% | 10% | 10% |
| Seed (`SEED`) | 61 | 61 | 61 |
| Reload cycles per cell (`RELOADS`) | 1 | 4 | 4 |

Dataset generation is fully deterministic from the shape + seed and is
identical across cells at the same shape (the generator never consults the
cell when building the dataset). The manifest carries a canonical
`dataset_sha256`; the full campaign rejects a cell whose digest differs.
`CHANGED_FRACTION` is a Bernoulli probability, not an exact cohort size: seed
61 changes 36/320 IRR filter lists at the full shape. Separately, the global A/B export marker changes output
for all observers, so `peers_changed=320` and the first-generation timing
percentiles cover 320 observers in the full receipt—not only the 36 members
whose input lists changed.
The multi-MB configs are **not** committed; they reproduce from the generator
and pinned inputs. Padding prefixes are /24s from
30.0.0.0–99.255.255.0 (disjoint from the announced table, the churn range,
and the bogon list).

## BMP Loc-RIB dump buffer receipt

`run-bmp-buffer-receipt.sh` reuses the canonical 320-member, 183,040-route,
seed-61 dataset (3,218,965 filter entries) with one BMP v3 RFC 9069 Loc-RIB collector.
It connects before 16-prefix/125 ms churn; two fresh daemons must match outcome class.

The sink accepts one TCP generation, caps each RFC 7854 frame at 1 MiB, caps
the total capture at 1 GiB, and has a 600-second deadline. It verifies the
exact Loc-RIB peer/table/capability identity, rejects base duplicates and
withdrawals, limits churn to the harness roster, and checks ordered IPv4/IPv6
unicast-plus-VPN EoRs. The manifest pins endpoint, version, and `loc_rib` view.
Complete requires every base prefix once, four EoRs, post-EoR churn, and a
scrape while the sole socket remains open. Overflow requires earlier EOF,
high-watermark 8,193, exactly 8,193 `live_buffer_full` drops, depth zero, and no
other drop. Both require one replay. This locates the 8,192-row boundary, not
general collector capacity or throughput.

The full run requires clean `origin/main`, quiet-host mutexes, and unused ports:

```bash
CONFIRM_BENCH_CRON_PAUSED=1 CONFIRM_NO_MAIN_PUSHES=1 ARTIFACTS_DIR=/tmp/bmp-buffer-receipt \
  bench/scale/irrreload/run-bmp-buffer-receipt.sh
```

`tests/bmp_buffer_receipt_check.rs` runs corrupt-fixture parser, inventory/order, metrics, and repeat proofs; full fleet remains a quiet-host receipt.

## Cells and reload mechanisms

| Cell | Policy representation | Reload mechanism |
|---|---|---|
| `rustbgpd-sighup` | `.rpol` per-member IRR filters rendered by `tools/rs-config-render` (the production IRR pipeline renderer) from a synthetic `arouteserver template-context` document, concatenated into one swapped file | copy generation file over live, `SIGHUP` |
| `rustbgpd-sighup-grouped-control` | the same `.rpol` policy and canonical dataset, with `per_client_best = false` so all 320 members share one update group | copy generation file over live, `SIGHUP`; standalone diagnostic control only |
| `rustbgpd-txn` | same dataset as inline `[policy.definitions]` chain-engine statements in a full candidate config TOML | copy candidate; streamed JSON Plan; explicit streamed Apply with the returned single-use plan token, snapshot token, and commit-confirm; assert pending v3 state, then confirm (`txn-apply.sh`) |
| `bird` | per-member prefix-set `define`s + import filters in the swapped include file | copy include, `birdc configure` |
| `openbgpd` | per-member `prefix-set`s + `source-as`/`prefix-set` allow rules in the swapped include file | copy include, `bgpctl reload` |

## Measurement definitions (precommitted)

All receiver-side, identical to the IXP matrix instrument; one row per
reload cycle per cell in `rows.csv` (the harness's `reloadstall_csv`
record):

- **Reload stall** — per-observer maximum inter-UPDATE gap in the 120 s
  window after the reload trigger (`*_maxgap_{p50,p95,max}_ms`), against
  the quiet control-window baseline. Wire-observable: timestamps are taken
  in the stubs after full wire framing + decode. The trigger timestamp is
  taken immediately before invoking the reload mechanism, so
  `birdc`/`bgpctl`/`rbgp` cells include their control-channel round-trip
  (SIGHUP has none; the txn cell's plan+apply round-trips are deliberately
  inside the window — they are that path's reload cost).
- **Completion** — time until an observer holds every expected unique
  non-self base-table prefix re-advertised with the new generation marker
  community (`completion_{p50,p95,max}_s`); duplicates never advance the
  window; churn prefixes are excluded by prefix range.
- **First generation output** —
  `changed_first_generation_update_{p50,p95,max}_ms` measures reload trigger
  to the first non-self base prefix carrying the expected generation marker.
  Unmarked output, stale markers, churn space, duplicates, and the observer's
  excluded own slice cannot start this clock.
- **RSS during reload** — `rss_before_mib`/`rss_after_mib` sampled from
  `/proc/<pid>` around each reload for the bare rustbgpd cells, plus the
  full process-tree 5 s-cadence sampler (`bench/scale/matrix/rss-sampler.sh`)
  for every cell (`rss.csv`; the only RSS instrument for the container
  cells).

Cross-daemon RSS comparisons use only the outer sampler, never the row-level
VmRSS fields (which are zero for container cells). For each reload, the
precommitted control statistic is the median `total_rss_kib` sample whose
integer epoch is in `[floor(trigger)-CONTROL_SECS, floor(trigger))`; the reload
statistic is the maximum sample in
`[floor(trigger), ceil(trigger+completion_max_s)]`. The trigger comes from the
logged `wall_us` and completion from that reload's emitted row. A missing
sample in either window invalidates the RSS comparison. The sampler sums RSS
across a process tree, so shared mappings can be double-counted; it prefers
`smaps_rollup` for readable processes and can fall back to VmRSS for
root-owned container processes. Close absolute differences are therefore not
treated as exact allocator comparisons.

**Startup and readiness windows** (harness parameters, not
measurements — none of them is timed into any reported number; they
only bound how long the harness waits before declaring a cell broken):

- **Daemon-start readiness**: the runner polls at 1 s cadence until
  the cell's daemon holds a listener on the BGP port (containers: also
  until `docker inspect` reports a nonzero daemon PID, retried — a
  single immediate inspect can race a slow start and record pid=0),
  with a hard ceiling of `START_TIMEOUT` (default **600 s**). A
  multi-MB IRR policy parse legitimately takes far longer than a
  small-config boot; the poll returns as soon as the daemon is ready,
  so a generous ceiling costs nothing on fast starts.
- **Stub connect**: each stub retries its TCP connect at 500 ms
  cadence for up to **120 s** (`CONNECT_WINDOW` in the reloadstall
  harness) before failing the cell — refused connects while the daemon
  is still absorbing a large config, or during accept-backlog spikes
  under the 64-stub establishment waves, are retries, not failures.
- **Convergence / reload-completion stall watchdogs**: base-table
  convergence and each reload's completion tracker allow up to
  **600 s** (`FIRST_OUTPUT_WINDOW`) for the first observed
  announcement of their phase — ingesting 183k routes through
  IRR-scale per-peer import chains, or re-parsing a multi-MB policy on
  SIGHUP, computes for minutes before anything reaches the wire — then
  abort after **120 s** (`STALL_WINDOW`) with no further observer
  progress. Completion and stall *measurements* are timestamp-based
  and unaffected by watchdog size.

**Acceptance / abort criteria** (a cycle emits no row, the cell fails):
any stub session down at reload validation, missing generation-marker
evidence, any daemon UPDATE that fails to decode, a nonzero reload-command
exit, daemon process-tree RSS > 100 GiB (cell aborted), or cell timeout
(`CELL_TIMEOUT`). Artifact roots are immutable: a failed/interrupted cell,
an inconsistent row set, or a different campaign fingerprint is never
overwritten. Preserve it and choose a fresh `ARTIFACTS_DIR`; matching passed
cells alone are resumable/skippable. Each passed cell seals its exact rows,
RSS samples, daemon and harness logs, manifest, provenance, and scenario roster;
resume revalidates that evidence and the root-row copy before skipping. A
missing or malformed root seal aborts the whole invocation before another cell
can append evidence.

Resume status is fingerprint-qualified. The fingerprint covers the exact Git
commit and dirty-state content, runner/generator/sampler/transaction scripts,
built daemon/CLI/renderer/harness binaries, Rust/Python/jq/Docker environment,
selected cells, shape and timing inputs, and the local content IDs behind
selected container image references. Each cell also retains `scenario.sha256`,
a relative-path/content-hash roster of the manifest and exact daemon runtime
inputs (not timestamped renderer receipts); its digest and the common dataset
digest are bound into that cell's provenance and pass status. A pass from any
other fingerprint or input digest cannot satisfy the new campaign. Root and
per-cell `provenance.json` retain the
fingerprint without hostnames, usernames, absolute paths, or other host-unique
identifiers.
Successful cells may delete their generated scenario only after retaining its
generator `manifest.json` alongside that provenance.

The full transaction cell retains only compact lifecycle evidence, never plan
or runtime token contents and never the multi-MiB candidate or v3 raw snapshot.
Each of its four measured B/A/B/A reloads proves a streamed committable Plan,
explicit use of that Plan's UUID-v4 single-use token, pending commit-confirm,
the canonical config-adjacent v3 locator plus fixed owner-only raw/metadata
files, full locator→metadata→raw path/digest/device/inode linkage, raw size in
`(10 MiB, 384 MiB]`, legacy-journal absence, and confirmed terminal cleanup.
After the final measurement boundary and before daemon teardown,
`txn-lifecycle.sh` applies the opposite B generation twice: explicit abort and
ten-second timeout must report `aborted` and `auto_reverted`, remove all v3
authority, and restore the exact A disk and effective-runtime hashes. A final
streamed Plan of A must be tokenless `NOOP`.

Because config-history's `SkippedOversize` outcome is internal, the retained
proof binds the public empty history entries and on-disk history roster before
and after every persist to the daemon's exact oversize warning (including a
byte count above 10 MiB). The verifier requires nine such warnings: boot, four
measured applies, abort apply/restore, and timeout apply/restore.
Offline verification recomputes the canonical provenance fingerprint, requires
the exact full-workload knobs and repeat tool/image identities, and re-parses
`scenario.sha256` against the manifest's safe `runtime_files` roster. Any
symlink in a retained receipt is invalid.

The RSS sampler is a required instrument: early/nonzero sampler exit or an
empty/malformed `rss.csv` fails the cell. The runner reaps the sampler after
the daemon exits and preserves all artifacts on failure.

For the two rustbgpd cells, the runner opts into the reloadstall harness's
`RELOADSTALL_PRE_CHURN_EVIDENCE_DIR` boundary. After base convergence and
before starting churn, the harness publishes `ready` and waits at most 60
seconds for a regular `ack`; absent means the historical harness path is
unchanged. The runner retries transiently unsettled evidence for at most 50
seconds, and atomically publishes `ack` only after accepting three production
Prometheus scrapes at least one second apart. Invalid evidence is never
acknowledged, so the cell fails closed with the boundary and attempt retained.

Every cell also opts into `RELOADSTALL_EVIDENCE_DIR`. After the final measured
rows are emitted, the harness keeps its stub sessions live and publishes
`ready`. Before atomically publishing `ack`, the runner verifies that the
daemon PID/start identity still matches the cell and records `process.tsv`.
The retained final `ready`/`ack` pair therefore binds process identity to the
measurement end rather than to a post-exit state with the stubs already gone.
Missing or mismatched evidence is never acknowledged and fails the cell.

At the full shape, the scrapes must show no Add-Path config, all 320 sessions
established, empty outbound queues, Loc-RIB exactly 183,040, exact per-peer Adj-RIB-In and
Adj-RIB-Out family rosters/counts, and a stable exact update-group topology.
The comparison cell requires 320 `per_client_best` peers, zero groups, 320
fallback peers, and every peer's group gauge at `-1`. The grouped control
requires no `per_client_best` peers, exactly one 320-member group, zero
fallback peers, and one shared nonnegative group ID. The last accepted scrape
must precede the harness's first wire-measurement trigger. The retained
`ready`, `ack`, timestamps, config, and raw scrapes are all in the cell's
checksum chain and are independently re-parsed by the four-root verifier.

**Cross-daemon run count and order**: four fresh artifact roots in fixed A/B/B/A order:
comparison A, grouped-control A, grouped-control B, comparison B. Each cell
gets a fresh daemon PID/start identity. This counterbalances host drift around
the diagnostic control without putting the control in the competitor table.
`verify-receipt.py campaigns` rejects reordered roots, reused process
identities, source/dataset/shape mismatches, non-quiet cells, broken seals, or
grouped rows in `comparison.csv`; it writes grouped rows only to
`grouped-control.csv`. The repeats are not statistically independent trials.

**Transaction run count and order**: two fresh full-shape roots in strict A/B
order. `verify-receipt.py transactions` requires the same clean commit,
dataset, shape, scripts, binaries, and platform, non-overlapping roots, and
distinct daemon PID/start identities. It independently checks all four cycles,
abort/timeout restoration, history-warning sequence, exact file roster,
quiet-host evidence, seals, and the absence of retained token contents.

**Host-quiet preconditions** (every full measured mode enforces): clean `HEAD`
exactly at `origin/main`, the canonical shape/seed, no `SKIP_PREFLIGHT`, a
passing `tests/soak/preflight.sh`, and exclusive ownership of the shared host
lock. Before every cell, two retained 1-minute-load samples at least 30 seconds
apart must both be below 2.0, ports 1790 and 9179 must be free, the artifact
filesystem must have at least 40 GiB available, and `pswpin`/`pswpout` must not
move between samples; cells retain their daemon PID/start identity.
Successful roots carry `COMPLETED` plus an exact `SHA256SUMS` roster and become
read-only. `SMOKE=1` skips the quiet gates because it is not a measurement.

## Comparability protocol

Mirrors the IXP matrix fairness notes (`docs/perf/ixp-matrix-2026-07.md`):

- **One harness, one instrument** for the three full-shape cells; same addressing, same
  churn, same completion semantics.
- **Same dataset, native idiom per daemon.** Every cell filters the same
  member/prefix dataset with the same semantic core — per-member
  (origin-AS ∈ member origin set) ∧ (prefix ∈ member filter list), plus a
  shared hygiene preamble (AS_PATH length cap 32, bogon reject:
  10.0.0.0/8, 192.168.0.0/16 — 172.16.0.0/12 deliberately excluded because
  the harness churn blocks live there) and the generation-marker export
  tag — expressed in each daemon's native form.
- **Each daemon reloaded by its operator-documented mechanism** at its
  documented route-server configuration (BIRD `rs client` + threads knob;
  OpenBGPD `transparent-as` + `nexthop qualify via default`; rustbgpd
  `route_server_client` + `per_client_best`).

Documented asymmetries (the honesty notes for the eventual receipt):

- **Reload-semantic asymmetry.** SIGHUP + `.rpol` swap re-parses only the
  policy files; `birdc configure` and `bgpctl reload` re-parse the entire
  config; the rustbgpd transactional path parses + diffs + classifies a
  full candidate config and round-trips plan/apply over gRPC. These are
  each path's documented reload operation — not the same amount of work.
- **The two rustbgpd cells use different policy engines.** The
  transaction seam rejects out-of-band `.rpol` content changes by design
  (`docs/reload-matrix.md`), so the txn cell carries the dataset as inline
  chain-engine definitions while the SIGHUP cell uses the production
  `.rpol` route-server representation. Cross-daemon comparisons should use
  the SIGHUP cell; the txn cell answers "what does the transactional seam
  cost for the same semantic change", not engine-vs-engine.
- **The txn cell is streamed and separate.** Plan and Apply send bounded chunks
  and accept a candidate up to 384 MiB, so `rustbgpd-txn` alone now selects the
  canonical 320-member shape. The runner rejects a measured candidate at or
  below the 10 MiB history boundary or above the streaming ceiling before
  starting measurements. The 10-member transaction remains smoke-only. Its
  rows and artifact roots never enter the cross-daemon table.
- **Hygiene depth differs slightly.** The rustbgpd SIGHUP cell carries the
  full rendered `rs-hygiene` (including the AS_SET-segment reject term);
  the chain engine and the BIRD/OpenBGPD cells carry the shared core
  (path-length + bogons) only. All hygiene is generation-static and
  constant-size, so it does not contribute to the reload delta being
  measured.
- **Bench plumbing edits on the rendered config.** The SIGHUP cell's
  `config.toml` is rs-config-render output with asserted, session-level
  patches for the loopback contract (listen port, runtime/UDS paths,
  `next_hop_ownership` dropped because the stubs use the synthetic
  10.9.x.y NEXT_HOP; BIRD gets `next hop keep` + glue routes and OpenBGPD
  `nexthop qualify via default` for the same reason; max-prefix ceilings
  disabled in the context). Rendered policy files are never edited.
- **Padding realism ceiling**: filter-list padding entries are all /24s;
  real IRR lists mix lengths. Constant across daemons and generations.
- **Path-hiding control is not another competitor.** The comparison's
  rustbgpd config explicitly uses `--path-hiding true --admit-churn true`.
  The standalone grouped control uses `false/true`. BIRD and OpenBGPD retain
  the same canonical dataset and churn admission, but path hiding is recorded
  as non-applicable in their manifests. Grouped-control rows diagnose the
  update-group fanout seam and never enter comparison or recommendation text.

## Running

```bash
# Smoke (pipeline proof, any host, ~minutes):
SMOKE=1 bench/scale/irrreload/run-irr-reload.sh

# Full campaign (quiet host only), exact A/B/B/A order and fresh roots:
ARTIFACTS_DIR=/tmp/irrreload-comparison-A bench/scale/irrreload/run-irr-reload.sh
ARTIFACTS_DIR=/tmp/irrreload-grouped-A bench/scale/irrreload/run-irr-reload.sh rustbgpd-sighup-grouped-control
ARTIFACTS_DIR=/tmp/irrreload-grouped-B bench/scale/irrreload/run-irr-reload.sh rustbgpd-sighup-grouped-control
ARTIFACTS_DIR=/tmp/irrreload-comparison-B bench/scale/irrreload/run-irr-reload.sh

python3 bench/scale/irrreload/verify-receipt.py campaigns \
  --output-dir /tmp/irrreload-verified \
  /tmp/irrreload-comparison-A /tmp/irrreload-grouped-A \
  /tmp/irrreload-grouped-B /tmp/irrreload-comparison-B

# Separate full-shape transaction receipt, repeated into fresh roots:
ARTIFACTS_DIR=/tmp/irrreload-txn-runA bench/scale/irrreload/run-irr-reload.sh rustbgpd-txn
ARTIFACTS_DIR=/tmp/irrreload-txn-runB bench/scale/irrreload/run-irr-reload.sh rustbgpd-txn

python3 bench/scale/irrreload/verify-receipt.py transactions \
  --output-dir /tmp/irrreload-txn-verified \
  /tmp/irrreload-txn-runA /tmp/irrreload-txn-runB
```

The runner builds what it needs (`rustbgpd`, `rbgp`, `rs-config-render`,
the harness), generates each cell's scenario under `/tmp/irr-<cell>` (short
paths: the gRPC UDS must fit `SUN_LEN`), runs one cell at a time, tears
down containers/daemons, and appends one row per reload to
`$ARTIFACTS_DIR/rows.csv`. At the full default, exit code 0 requires the
three comparable cells to pass and produce exactly `RELOADS` rows apiece.
Container images: `bird:3.3.1`
(built from `tests/interop/Dockerfile.bird3`) and `openbgpd/openbgpd:9.1`.
