# reloadstall

Deliberate manual performance harness: CI compiles, lints, and unit-tests it, but the measured run is operator-initiated.

Route-server-scale policy-reload UPDATE-stall driver.

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

Reload and flapstorm runs gate initial convergence on exact unique-prefix bitmap
coverage at every observer: the full table minus its own slice. Duplicate,
own-slice, and out-of-range announcements cannot advance completion;
the bitmap is disarmed before the pre-churn evidence barrier and churn begin.
One `first_exact_bitmap` receipt records the mode and fleet coverage. Historical
zero-reload, non-flap convergence-only runs retain the cumulative announcement
gate unchanged.

Depends only on `crates/wire` (wire encode/decode for the stub sessions).

## Backs

- `docs/perf/reload-stall-2026-07.md` (LAN-333). The full daemon-side scenario
  (700 `[[neighbors]]` route-server-client blocks, `member-in` / `member-out`
  rpol chains, gRPC UDS, and the two policy generations) is pinned there.

## Build and run

Member of the `bench/scale` workspace (not the root workspace — build it
explicitly):

```text
cargo build --release --manifest-path bench/scale/reloadstall/Cargo.toml
./bench/scale/target/release/reloadstall <n_peers> <total_prefixes> <daemon_port> \
    <daemon_pid> <policy_live> <policy_a> <policy_b> <reloads> <control_secs> \
    [changed_peers]
```

The daemon must already be running (load-gated `--release` start) with
`n_peers` route-server-client neighbors and its live policy file at
`<policy_live>`; `<policy_a>` / `<policy_b>` are the two generations copied over
it on alternating reloads.

## Arg contract

From `src/main.rs` (fewer than 9 positional args prints the usage string and
exits 2):

```text
reloadstall <n_peers> <total_prefixes> <daemon_port> <daemon_pid> \
    <policy_live> <policy_a> <policy_b> <reloads> <control_secs> \
    [changed_peers] [reload_cmd] [--flapstorm K] [--convergence-only]
```

- `n_peers` — stub sessions to establish (`total_prefixes` must divide evenly).
- `total_prefixes` — base-table size; each stub owns `total/n_peers` /24s.
- `daemon_port` / `daemon_pid` — the running daemon's listen port and PID (PID
  is used for SIGHUP and RSS sampling).
- `policy_live` — the daemon's live `.rpol` file (copied over each reload).
- `policy_a` / `policy_b` — the two policy generations (alternated per reload).
- `reloads` — number of SIGHUP reload cycles.
- `control_secs` — quiet control-window length (baseline inter-UPDATE gap).
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
  3 rounds, per-round percentiles plus `flapstorm_csv` records.
- `RELOADSTALL_SESSION_NOTIFICATION_METRICS_ADDR` — optional B2 receipt seam,
  valid only with `--flapstorm`. It must be a loopback socket address with a
  nonzero port. The exact 700-peer/400400-prefix/50-flap shape polls the
  daemon's Prometheus endpoint at ten phase boundaries and emits
  `session_notification_receipt` rows after the notification population has
  reached zero. This proves dequeue accounting only: the monotonic lifetime
  high-water value is not a per-round peak, capacity, latency, or bound.
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

Cross-daemon cells generate their route-server configs with
`gen-bird-scenario.py` / `gen-obgpd-scenario.py` (same addressing contract)
and are sequenced by `bench/scale/matrix/run-matrix.sh`. The runner defaults
to the frozen `historical` comparator generation (BIRD 3.3.1 / OpenBGPD 9.1).
Set `COMPETITOR_GENERATION=current` to select the explicit current pair:

- BIRD 3.3.2, built as `bird:v3.3.2-m101` from the checksum-pinned
  `tests/interop/Dockerfile.bird-v332`;
- OpenBGPD 9.2 at
  `openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9`.

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
