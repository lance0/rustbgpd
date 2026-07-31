# irrreload — IRR-scale reload-receipt matrix

Reload stall + completion under live sessions with a realistic multi-MB
IRR-generated member policy, for rustbgpd on **both** reload paths (SIGHUP
parse-then-swap and the gRPC transactional apply) versus BIRD 3.3.x and
OpenBGPD 9.x.

This directory is the campaign runner and protocol. The instrument is the
existing `bench/scale/reloadstall` harness, unchanged — real BGP stub
sessions over loopback TCP, receiver-side timestamps, generation-marker
completion tracking — driven by `bench/scale/reloadstall/gen-irr-scenario.py`,
which emits all four cells from one seeded dataset.

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

| Parameter | Smoke (`SMOKE=1`) | Measured default |
|---|---|---|
| Members (`N_MEMBERS`) | 10 | 320 |
| Announced base table (`TOTAL_PREFIXES`) | 100 (10 × /24 each) | 183,040 (572 × /24 each) |
| Per-member IRR filter list (`MIN_LIST`–`MAX_LIST`) | 100 | log-uniform 1,000–40,000 entries |
| Generation-changed members (`CHANGED_FRACTION`) | 10% | 10% |
| Seed (`SEED`) | 61 | 61 |
| Reload cycles per cell (`RELOADS`) | 1 | 4 |

Dataset generation is fully deterministic from the shape + seed and is
identical across cells (the generator never consults the cell when building
the dataset). The multi-MB configs are **not** committed; they reproduce
from the generator alone. Padding prefixes are /24s from
30.0.0.0–99.255.255.0 (disjoint from the announced table, the churn range,
and the bogon list).

## Cells and reload mechanisms

| Cell | Policy representation | Reload mechanism |
|---|---|---|
| `rustbgpd-sighup` | `.rpol` per-member IRR filters rendered by `tools/rs-config-render` (the production IRR pipeline renderer) from a synthetic `arouteserver template-context` document, concatenated into one swapped file | copy generation file over live, `SIGHUP` |
| `rustbgpd-txn` | same dataset as inline `[policy.definitions]` chain-engine statements in a full candidate config TOML | copy candidate, `rbgp config plan` + `config apply` with the plan's snapshot token (`txn-apply.sh`) |
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
(`CELL_TIMEOUT`). Failed cells keep their artifacts and are published with
their mechanism, not silently rerun (`status` files make the campaign
resumable per cell).

Resume status is fingerprint-qualified. The fingerprint covers the exact Git
commit and dirty-state content, runner/generator/sampler/transaction scripts,
built daemon/CLI/renderer/harness binaries, Rust/Python/jq/Docker environment,
selected cells, shape and timing inputs, and the local content IDs behind
selected container image references. Each cell also retains `scenario.sha256`,
a relative-path/content-hash roster of the generated config bundle; its digest
is bound into that cell's provenance and pass status. A pass from any other
fingerprint or config-bundle digest is discarded and rerun; its old rows cannot
satisfy the new campaign. Root and per-cell `provenance.json` retain the
fingerprint without hostnames, usernames, absolute paths, or other host-unique
identifiers.
Successful cells may delete their generated scenario only after retaining its
generator `manifest.json` alongside that provenance.

The RSS sampler is a required instrument: early/nonzero sampler exit or an
empty/malformed `rss.csv` fails the cell. The runner reaps the sampler after
the daemon exits and preserves all artifacts on failure.

**Run count**: two full independent campaign runs minimum (fresh daemon
starts, same cell order) so run-to-run spread is visible — run B into a
separate `ARTIFACTS_DIR`.

**Host-quiet preconditions** (measured mode enforces): the campaign starts
only after `tests/soak/preflight.sh` passes (competing-workload, host-lock,
disk and mutex checks; `SKIP_PREFLIGHT=1` to override deliberately), plus a
1-min loadavg < 2.0 gate before each cell and 300 s cool-downs between
cells. `SMOKE=1` skips all quiet gates because it is a pipeline proof, not
a measurement.

## Comparability protocol

Mirrors the IXP matrix fairness notes (`docs/perf/ixp-matrix-2026-07.md`):

- **One harness, one instrument** for all cells; same addressing, same
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
- **The txn cell is size-capped today.** The candidate travels inside one
  gRPC message and the daemon's tonic server uses the default ~4 MiB
  decode limit, and the chain-engine TOML encoding is several times larger
  than the equivalent `.rpol`. At the measured default shape the candidate
  far exceeds the cap, so the transactional cell must run at the largest
  shape that fits (or the daemon must grow a raised/streamed limit first —
  a finding of this harness, to be stated in the receipt either way).
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

## Running

```bash
# Smoke (pipeline proof, any host, ~minutes):
SMOKE=1 bench/scale/irrreload/run-irr-reload.sh

# Measured campaign (quiet host only — preflight-gated), two runs:
bench/scale/irrreload/run-irr-reload.sh
ARTIFACTS_DIR=/tmp/irrreload-artifacts-runB bench/scale/irrreload/run-irr-reload.sh
```

The runner builds what it needs (`rustbgpd`, `rbgp`, `rs-config-render`,
the harness), generates each cell's scenario under `/tmp/irr-<cell>` (short
paths: the gRPC UDS must fit `SUN_LEN`), runs one cell at a time, tears
down containers/daemons, and appends one row per reload to
`$ARTIFACTS_DIR/rows.csv`. Exit code 0 requires every requested cell to
pass and produce at least `RELOADS` rows. Container images: `bird:3.3.1`
(built from `tests/interop/Dockerfile.bird3`) and `openbgpd/openbgpd:9.1`.
