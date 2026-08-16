# Soak Acceptance Gates (precommitted)

Precommitted pass/fail criteria for every soak scenario shipped in
`tests/soak/`. This document is written **before** a soak window opens;
a soak receipt quotes the bounds from here (at the receipt's git SHA)
and publishes measured-vs-precommitted for every gate — **including
when the verdict is red**. A receipt whose gates were chosen after the
run is not evidence.

Three standing rules govern every gate in this file:

1. **Gates are precommitted.** The bound, the metric evidencing it, and
   the abort criteria are fixed here before anything runs. Receipts may
   publish red; they may not renegotiate bounds.
2. **A gate's metric must refresh on every scenario path.** Each gate
   below names the exact metric / CSV column / log that evidences it
   *and* the scenario action that moves it. A gate on a metric its
   scenario never updates is a false green. Metric names below are
   verified against `crates/telemetry/src/metrics.rs` at the time of
   writing; re-verify on rebase (the per-peer intern gauge was replaced
   by the daemon-wide `bgp_rib_attr_intern_global_size` long ago —
   never cite a dead metric).
3. **Abort criteria preserve evidence.** An aborted soak is a data
   point, not a discard. See "Abort criteria" below.

Enforced bounds live in the analyzers
(`tests/soak/analyze-soak-*.py`, `tests/soak/analyze-*.py`); this
document adds the window-level floors and the evidence mapping. Where
a bound is chosen here rather than inherited from an analyzer, the
rationale is stated inline.

## Abort criteria (all scenarios)

A soak stops early — and the run is recorded as **aborted**, never
silently rerun — when any of the following occurs:

| Abort trigger | Detection |
|---------------|-----------|
| Daemon process restart mid-soak | Counter monotonicity break (e.g. `bgp_messages_sent_total` decreases between samples), or the harness's own restart detection. A restart flattens the slope regression and would hide a leak, so the run is invalid as a *pass* but preserved as evidence of the crash. |
| Harness step fails closed | The runners are `set -euo pipefail` and (since the fail-closed hardening) exit non-zero when required evidence is missing (e.g. GR active/stale not observed, apply cycle fails, injection RPC errors). |
| Metrics endpoint unreachable for > 5 consecutive samples | `curl` scrape failures in the sampler — a blind sampler cannot certify anything. |
| Host disk < 5 GB free | Daemon logs grow multi-GB over multi-day windows; running the disk to zero corrupts the evidence it was collecting. |
| Competing workload appears | Host-lock contention, an unexpected clab topology, or a bench dispatch. The bench/soak `flock` mutex makes this structural, but a manual discovery also aborts. |

**On abort, evidence is preserved, in this order:**

1. Leave the topology **up**. Copy daemon logs out of every container
   (`docker cp` / `docker logs`) into the run directory *before* any
   `containerlab destroy`.
2. Keep the entire `tests/soak/runs/<run-id>/` directory. `samples.csv`
   is written incrementally, so the partial series survives.
3. Run the scenario's analyzer over the partial CSV and record its
   verdict (`fail` is expected and fine).
4. Fill a receipt from `docs/soaks/soak-receipt-template.md` with the
   abort record section completed (trigger, UTC time, elapsed, artifacts
   preserved).

Do not stitch a resumed run onto an aborted CSV — the analyzer slope
regression would silently re-introduce a warmup window mid-series.
Rerun from scratch.

## Primary multi-day scenarios

The three fail-closed harnesses below are the pre-designed
failure-injecting set for multi-day windows. Analyzer bounds were
calibrated on the archived 24 h receipts under `docs/soaks/` (RSS
plateaus of 20–30 MB with slopes ≤ 0.2 MB/h on clean builds), so the
1.0 MB/h fail line has an order-of-magnitude margin over observed-clean
while still catching a ~25 MB/day leak.

The slope gates are precommitted for windows of **24 h or longer**. On
sub-hour smokes and rehearsals the allocator's settle dominates the
regression and overshoots the hourly bound (the archived 24 h receipts
show cumulative slope monotonically tightening from > 1 MB/h at hour 2
to < 0.2 MB/h at terminal); a short run's red slope gate is a
small-window artifact, not leak evidence — exactly as a short run's
green slope would not be clean evidence.

### 1. GR-restart intern-gc — `run-soak-gr-restart-intern-gc.sh`

Injection: repeated peer daemon restart (`killall -9 bgpd` in the FRR
container; watchfrr restarts it, harness-supervised past watchfrr's
restart-abandon threshold — never `frrinit.sh stop`, which kills
the container's PID 1 and destroys the clab veth) driving rustbgpd
through session-down → stale-mark → reconnect → EoR → stale-clear →
intern GC. Analyzer: `analyze-soak-gr-restart.py`.

| Gate | Precommitted bound | Evidence | Refreshes under scenario via |
|------|--------------------|----------|------------------------------|
| Intern-table slope | < 1.0 entries/h | `bgp_rib_attr_intern_global_size` gauge → CSV `intern_size` | Re-announce after every peer restart re-interns attributes; `gc_intern_table` reclaims after stale-clear. The sampler also fires inside the restart routine at the GR-active and post-clear points, so the column moves every cycle. |
| RSS slope (post-warmup) | < 1.0 MB/h | `/proc/<pid>/status` VmRSS → CSV `rss_mb` | Allocation churn on every restart/re-announce cycle. |
| Peak RSS | < 512 MB | CSV `rss_mb` max | Same. |
| Restart cycles completed | ≥ 0.8 × (duration ÷ `RESTART_INTERVAL_SEC`) | CSV `restart_cycles` max | Incremented by the harness on every completed cycle. Analyzer floor is ≥ 1; the window floor (chosen here) rejects a run that silently stalled mid-window. 0.8× rather than 1.0× because per-cycle work (GR polling + re-establish, ~15–45 s) rides on top of the interval — a 72 h run at the 300 s default must show ≥ 691 cycles. |
| GR evidence ordered | positive `gr_active`+`stale` observed, then both clear, every cycle | `bgp_gr_active_peers`, `bgp_gr_stale_routes` → CSV columns | Set by GR entry on peer death; cleared by EoR + stale-clear. Harness fails closed mid-run if either phase is not observed within 30 s. |
| Session recovered at end | Final CSV `bgp_established` == 1 | FRR `show bgp neighbors` → CSV `bgp_established` | Every restart flips it 1→0→1. |
| Re-establish latency | ≤ 60 s after peer returns | harness `wait_established 60` (fail-closed), `cycles.log` | Checked every cycle. |
| Zero crash | no daemon restart | `bgp_messages_sent_total` monotone across samples (abort criterion) | Counter advances with every keepalive/update. |

### 2. Hot-reload (config live-apply churn) — `run-soak-hot-reload.sh`

Injection: transactional config churn — `rbgp config plan` →
`config apply` with a mutated candidate every `APPLY_INTERVAL_SEC`.
Analyzer: `analyze-soak-hot-reload.py`.

| Gate | Precommitted bound | Evidence | Refreshes under scenario via |
|------|--------------------|----------|------------------------------|
| Intern-table slope | < 1.0 entries/h | `bgp_rib_attr_intern_global_size` → CSV `intern_size` | Config-apply rebuild paths touch attribute interning; the gauge is sampled every 30 s regardless. |
| RSS slope (post-warmup) | < 1.0 MB/h | VmRSS → CSV `rss_mb` | Every plan/apply allocates a candidate world. |
| Peak RSS | < 512 MB | CSV `rss_mb` max | Same. |
| Apply accounting exact | cycles == ok + fail, fail == 0, ok ≥ 1 | CSV `apply_cycles`, `apply_ok`, `apply_fail` | Incremented per apply attempt; a swallowed failure breaks the equality (fail-closed). |
| Apply cycles completed | ≥ 0.9 × (duration ÷ `APPLY_INTERVAL_SEC`) | CSV `apply_cycles` | Window floor, same stall rationale as scenario 1; 0.9× (tighter than scenario 1) because an apply cycle is seconds of work against a 120 s interval. |
| Session-flap budget | flap delta == 0 across the whole run | `rbgp neighbor -j` `flap_count` → CSV `flap_count` (backed by `bgp_session_flaps_total`) | Sampled every interval; a live-apply that bounces the session moves it immediately. |
| Session uptime | nondecreasing | CSV `uptime_seconds` | Resets on any reconnect — catches a flap that lands between flap-count samples. |
| Session established at end | Final CSV `bgp_established` == 1 | CSV `bgp_established` | Scraped from FRR every sample. |

### 3. Inject-churn (gRPC route injection) — `run-soak-inject-churn.sh`

Injection: sustained `InjectionService` AddPath/DeletePath churn
(`rbgp rib add`/`delete`), bounded rotating prefix pool. Analyzer:
`analyze-soak-inject-churn.py`.

| Gate | Precommitted bound | Evidence | Refreshes under scenario via |
|------|--------------------|----------|------------------------------|
| Intern-table slope | < 1.0 entries/h | `bgp_rib_attr_intern_global_size` → CSV `intern_size` | Every injected path interns an attribute set; deletes release. |
| RSS slope (post-warmup) | < 1.0 MB/h | VmRSS → CSV `rss_mb` | Continuous add/delete allocation churn. |
| Peak RSS | < 512 MB | CSV `rss_mb` max | Same. |
| Churn cycles completed | ≥ 0.5 × ((duration − warmup) ÷ `CHURN_INTERVAL_SEC`) | CSV `churn_cycles` | Window floor. 0.5× of nominal because each batch is 2 × `CHURN_BATCH` sequential `docker exec` RPCs whose wall time rides on top of the 5 s interval; the receipt must state the achieved cadence. At defaults a 72 h run must show ≥ 25 908 cycles. |
| Final consumer convergence | FRR route count == live target, exactly, within 30 s of churn end | FRR `show bgp ipv4 unicast` → CSV `frr_route_count` vs `live_target` | The consumer count tracks every add/delete batch; an off-by-anything at terminal means a lost announce or withdraw. |
| Session-flap budget | flap delta == 0 | CSV `flap_count` / `uptime_seconds` (as scenario 2) | Sampled every interval. |
| Session established at end | Final CSV `bgp_established` == 1 | CSV `bgp_established` | Every sample. |
| Injection RPC failures | 0 (fail-closed) | harness exit path + `churn.log` | Every `rbgp rib` call is checked; a failed RPC aborts the run. |

## Additional shipped scenarios

These harnesses are part of the suite and can anchor a multi-day window
when their subsystem is in scope. Bounds are the analyzer / README
values; window floors follow the same 0.9× rule as above.

### 4. M33 EVPN scale — `run-m33-soak.sh` (`analyze-soak.py`)

50 k EVPN Type 2 routes + continuous tester churn. Gates: RSS slope
< 1.0 MB/h fail / < 0.5 clean; peak RSS < 512 MB; session-flap delta
== 0 (flap/drop counters in `samples.csv`); outbound route-drop delta
== 0; zero gRPC health failures; exactly three valid peer-session gauges
and all Established in the final sample; restart detection via counter
monotonicity (`bgp_messages_sent_total`). Abort: two
consecutive gRPC health-check failures.

### 5. M37 local-origination MAC churn — `run-m37-local-origination-churn-soak.sh`

Bounded bridge-FDB churn against the local-MAC origination pipeline.
Precedent: the 2026-05-18 24 h PASS (`soak-m37-local-origination-churn-24h.md`,
slope 0.184 MB/h, ledger 430 400 == 430 400). Gates: session
Established outside deliberate windows; `local_fdb_count` /
`frr_type2_count` hold at the live target and drain to 0 at terminal;
`evpn_local_originations_total{action="inject"}` ==
`{action="withdraw"}` at terminal (ledger balance);
`evpn_local_origination_errors_total` == 0;
`evpn_local_observations_dropped_total` == 0;
`evpn_duplicate_mac_moves_total` == 0 unless deliberately injected;
post-warmup RSS slope < 1.0 MB/h (precedent says expect ≲ 0.2).

### 6. M67 link-drain churn — `run-m67-link-drain-churn-soak.sh` (`analyze-m67-link-drain-soak.py`)

Repeated real carrier down/up on the active PE's attachment circuit.
Gates (analyzer defaults): verdict `pass`; per-node RSS slope
< 1.5 MB/h once past `--min-slope-seconds` (1800 s); peak RSS
< 512 MB; measured failover blackout ≤ 30 000 ms and drain release
≤ 30 000 ms per cycle (a `-1` unmeasured sentinel fails the cycle —
a missing prober log can never read as a perfect 0 ms failover);
cycle count ≥ floor; session transients ≤ 2 samples and both sessions
Established in the final CSV row; docker restart counters flat;
`pe1_operator_drain` stays 0 (the link stimulus must not leak into the
operator-drain reason).

### 7. Gate 8b BUM-state — `run-gate8b-soak.sh` (`analyze-gate8b-soak.py`)

DF flips via PE2 container stop/start, including setup-script replay, current
session recovery, and log-tail reattachment. Gates: per-PE RSS slope < 1.5 MB/h;
peak RSS < 512 MB; DF transition counters (`evpn_df_role_changes_total`)
monotone — a reset means an unplanned daemon restart; ≥ 1 full flip
cycle (window floor 0.9× applies); the single terminal row has
`pe2_running = 1` and both `pe*_session_established = 1`.

### 8. Gate 8b MAC-churn — `run-gate8b-mac-churn-soak.sh`

Scenario 7 plus sustained FDB churn and RFC 7432 §15.1 mobility moves.
This runner flips only the in-container daemon process (SIGTERM; opt-in SIGKILL)
so the netns and FDB survive, and retains its before/after
`verify_topology_link` tripwire. Its terminal recovery must restore the current
sessions and preserve that topology; cumulative establishment counters are
diagnostic only.
Analyzer coverage is scenario 7's (`analyze-gate8b-soak.py`); the
MAC-churn-specific gates are precommitted here and read from
`samples.csv`: `evpn_local_origination_errors_total` == 0 (CSV
`pe*_local_orig_errors`); observation drops == 0 (`pe*_local_obs_drops`);
receiver `extern_learn` FDB count stable around the pool target
(`pe*_fdb_extern_learn`); duplicate-MAC moves advance **only** with
harness mobility batches (`pe*_dup_mac_moves` vs `churn_moves_total`);
drift-recovery counters bounded and `pe*_drift_disabled` == 0.
Known gap: these are manual-inspection gates until a dedicated
analyzer exists — a receipt must include the inspection outcome per
gate, not just the base analyzer verdict.

### 9. Gate 9 slice 6 symmetric IRB — `run-gate9-slice6-soak.sh`

Tenant Type 5 add/del churn. Gates (README): per-PE RSS slope
< 1.0 MB/h; peak RSS < 400 MB; `bgp_established == 1` on every
post-warmup sample (flap budget 0); `pe1_installed_routes == 1` on
every post-warmup sample; `tenant_present` ↔ `pe1_observed_routes`
agree within one sample interval (wake-path latency ceiling);
`churn_cycles` strictly monotone.

### 10. Route-server flagship (SIGHUP reload + max-prefix trip) — `run-soak-rs-flagship.sh` (`analyze-soak-rs-flagship.py`)

The flagship shape on a bare-host daemon: 1000 real eBGP route-server-client
sessions × 400 routes each (400 k total), driven by the
`bench/scale/reloadstall` engine with its steady churn running throughout.
Two serialized injections: a real SIGHUP policy-file reload every
`RELOAD_INTERVAL_SEC` (default 1800 s → 48/24 h), each verified by the
engine's generation-marker completion barriers, and a max-prefix
trip/timed-restart cycle every `TRIP_INTERVAL_SEC` (default 14 400 s →
6/24 h) on the designated member (stub 0, `127.1.0.1`,
`max_prefixes = routes + 50`, `max_prefix_restart_seconds = 120`).

RSS bounds rationale: the ceiling is calibrated from the
`bench/scale/route-server-1000` retained receipt, whose one-shot
4-reload run at this exact shape enforces a 2 GiB process-tree ceiling;
repeated reload cycles add glibc allocator retention (a known-benign
pattern — see the LAN-461 finding: jemalloc erases it, it is not an
intern/RIB leak), so the soak ceiling adds 1 GiB of reload-cycle
headroom (3 GiB). Because that retention front-loads, the slope gate
bounds only the LATE window (final 25 % of the run), not the early
settle; 10 MB/h is well above the ±30–50 MiB allocator-arena noise
floor averaged over ≥ 6 h of 30 s samples, while still catching a
~240 MB/day leak. The late-window slope gates are evaluated only when
the late window spans ≥ 1 h (`--min-slope-seconds`); on shorter smokes
the analyzer records the values and annotates them as not evaluated —
never as silent green.

| Gate | Precommitted bound | Evidence | Refreshes under scenario via |
|------|--------------------|----------|------------------------------|
| Session floor | `established == 1000` on every post-warmup sample, EXCEPT exactly `999` inside a declared trip window (`announce_over` → `reestablished` ± one sample interval, from `cycles.log`) for the designated member only | sum of `bgp_peer_session_established` → CSV `established`; windows from `cycles.log` | Every trip flips the designated member 1→0→1; reload barriers fail the engine closed if any other session drops. |
| Reload accounting exact | issued == barrier-verified complete; complete ≥ 0.9 × planned | `cycles.log` `reload N issued` (engine SIGHUP marker) / `reload N complete` (only after the engine's completion + marker barriers and integrity check pass) | Every reload cycle appends both lines; a reload whose barrier never completes stalls the engine's fail-closed watchdog. |
| Trip accounting exact | executed == planned; per cycle the full evidence chain: breach counter reaches exactly N, hold-down countdown observed via `rbgp neighbor -j` (`max_prefix_restart_remaining_millis`, action `restart`), re-Established ≤ `max_prefix_restart_seconds` + 60 s after teardown, post-recovery `usage == routes`, `limit == max_prefixes`, `usage + headroom == limit`; zero unexpected latch-offs | `cycles.log` trip lines; `bgp_max_prefix_exceeded_total`, `bgp_max_prefix_usage/limit/headroom` (scope `aggregate`) | Each trip cycle drives breach → teardown → countdown → timed restart → compliant re-announce; the runner polls the CLI and metrics inside every window and fails closed on any missing link. |
| Exceeded-counter exact | final `bgp_max_prefix_exceeded_total` == executed trips | CSV `max_prefix_exceeded_total` | Incremented once per deliberate breach; any spurious latch-off breaks the equality. |
| Session-flap budget exact | flap delta over the run == executed trips (one per deliberate teardown) | sum of `bgp_session_flaps_total` → CSV `flaps_total` | Each trip teardown adds exactly one flap; reload cycles must add zero (the engine's per-reload `sessions_up` integrity check backs this). |
| Peak RSS | < 3072 MB (rationale above) | daemon process-tree RSS → CSV `rss_mb` | Full-table re-advertisement on every reload; teardown/re-announce churn on every trip. |
| RSS late-window slope | < 10 MB/h over the final 25 % of the run (evaluated only when that window ≥ 1 h; rationale above) | CSV `rss_mb` | Same. |
| Intern-table late-window slope | < 100 entries/h over the same window (the scenario's attribute universe is fixed; reload re-interning must return to plateau) | `bgp_rib_attr_intern_global_size` → CSV `intern_size` | Every reload re-interns per-chain attributes; GC reclaims after transition. |
| Counter monotonicity (no restart) | `bgp_messages_sent_total` never decreases between samples | CSV `msgs_sent_total` | Advances with every keepalive/UPDATE across 1000 sessions; a decrease means a daemon restart (abort criterion). |
| readyz availability | HTTP 200 within 250 ms on every sample (the route-server-1000 receipt enforces this bound during reloads at this exact shape) | CSV `readyz_code`, `readyz_ms` | Probed every sample, including mid-reload and mid-trip. |
| Minimum sample count | ≥ 0.9 × (`SOAK_SECONDS` ÷ `SAMPLE_INTERVAL`) | CSV row count | One row per interval; scrape failures skip the row (and ≥ 5 consecutive failures abort). |
| No abort record | zero `ABORT:` lines | `cycles.log` | The runner writes one before any fail-closed exit (daemon death, blind sampler, evidence deadline, disk floor, watchdog). |

### 11. Route-reflector flagship (reflection correctness under churn) — `run-soak-rr-flagship.sh` (`analyze-soak-rr-flagship.py`)

The documented RR flagship shape on a bare-host daemon: 1000 real iBGP
route-reflector-client sessions × 100 routes each (100 k total, the
`docs/cookbook/route-reflector.md` / 1000-peer-scale-receipt shape),
driven by the `bench/scale/reloadstall` engine's iBGP-RR mode
(`RELOADSTALL_IBGP_RR_ASN`) with its steady churn running throughout.
No SIGHUP reloads and no max-prefix trips — scenario 10 covers those;
this receipt's job is the flagship-RR shape + churn + stability. The
24 h window is the engine's `RELOADSTALL_IBGP_RR_HOLD_SECS` hold (one
fail-closed status line per minute), closed by the terminal
reflected-delivery verification: every observer re-requests the
daemon's Adj-RIB-Out with a Normal ROUTE_REFRESH and must complete its
full-table-minus-own-slice bitmap exactly (99 900 non-self prefixes per
observer).

RSS bounds rationale: calibrated from the in-process rrharness
flood-1000×100k receipt, which converges at 213 MiB manager-direct at
this exact route shape. Real transport adds 1000 TCP sessions,
per-peer Adj-RIB-Out state, and update-group buffers on top; the
historical real-transport measurement at this shape is the DATED
419 MiB scratch-harness figure (quoted as calibration input only, not
as a refreshed number — LAN-694). The 1024 MB ceiling is ~2.4× that
dated transport figure: wide enough that allocator-arena noise
(±30–50 MiB at 100p×1k) and measurement drift cannot trip it, tight
enough to catch a leak of a few hundred MB. There are no reload cycles
here, so no glibc reload-retention headroom is added (contrast
scenario 10's 3 GiB). The late-window slope bounds match scenario 10:
10 MB/h is above the arena noise floor averaged over a ≥ 6 h late
window while catching a ~240 MB/day leak; slope gates are evaluated
only when the late window spans ≥ 1 h (`--min-slope-seconds`), else
recorded and annotated as not evaluated — never silent green.

| Gate | Precommitted bound | Evidence | Refreshes under scenario via |
|------|--------------------|----------|------------------------------|
| Session floor | `established == 1000` on every post-warmup sample, no exceptions (this scenario has no deliberate teardowns) | sum of `bgp_peer_session_established` → CSV `established` | Every churn UPDATE rides the sessions; the engine's per-minute hold check fails closed on any drop, and the sampler sees it within one interval. |
| Session-flap budget exact | flap delta over the run == 0 | sum of `bgp_session_flaps_total` → CSV `flaps_total` | Any reconnect increments it; there is no legitimate source of flaps in this scenario. |
| Terminal reflected-delivery exact | engine `rr_terminal_receipt`: `min_unique == max_unique == expected == 99 900`, `sessions_up == 1000`, `parse_errors == 0` — the load-bearing correctness gate | `cycles.log` `rr_terminal_receipt` line (engine fails closed on the same equality before emitting it; the analyzer re-checks independently) | The terminal ROUTE_REFRESH forces the daemon to re-send every observer's Adj-RIB-Out after 24 h of churn; a single lost, duplicated-as-missing, or mis-reflected prefix breaks the exact equality. |
| Churn-cycle floor | final `churn_cycles` ≥ 0.5 × 64 × `SOAK_SECONDS` (8 churners × one flap message per 125 ms nominal; 0.5× tolerates timer drift + send backpressure, same rationale as scenario 3's floor), nondecreasing across hold lines | engine churn counter → `cycles.log` `rr_hold` lines + `rr_terminal_receipt` `churn_cycles` | Incremented on every churner announce/withdraw actually written to a live session; a wedged churner or dead session stalls it. |
| Reflection under churn | churn add + withdraw propagate to the full fleet for the whole window | CSV `msgs_sent_total` advancing every sample (1000-session fan-out of every churn flap) + the terminal gate above (a daemon that stopped reflecting cannot re-deliver an exact table) | Churners flap dedicated blocks every 125 ms; the daemon reflects each to 999 other clients. |
| Max-prefix flat | `bgp_max_prefix_exceeded_total` == 0 on every sample (no bounds configured; any latch is spurious enforcement) | CSV `max_prefix_exceeded_total` | Column kept from the shared sampler; the scenario never breaches. |
| Peak RSS | < 1024 MB (rationale above) | daemon process-tree RSS → CSV `rss_mb` | 100 k-route table held + churn allocation/free every 125 ms. |
| RSS late-window slope | < 10 MB/h over the final 25 % of the run (evaluated only when that window ≥ 1 h; rationale above) | CSV `rss_mb` | Same. |
| Intern-table late-window slope | < 100 entries/h over the same window (the attribute universe is fixed; churn re-interns the same attribute sets) | `bgp_rib_attr_intern_global_size` → CSV `intern_size` | Every churn announce interns; every withdraw releases. |
| Counter monotonicity (no restart) | `bgp_messages_sent_total` never decreases between samples | CSV `msgs_sent_total` | Advances with every keepalive/UPDATE across 1000 sessions; a decrease means a daemon restart (abort criterion). |
| readyz availability | (a) HTTP 200 within 250 ms on every sample inside the hold (before the terminal-refresh window) — where the operational claim lives, unchanged; (b) inside the terminal-refresh window (from the engine's `rr_terminal refresh` marker onward) every sample must record an HTTP response, any code: `/readyz` is a deadline-bounded active core-actor probe that fails closed (`src/metrics_server.rs`), so a 503 is the documented busy signal under the deliberate 1000-way simultaneous full-table refresh avalanche — a worst case present in no operational claim — while a timeout or refused connection still fails; (c) recovery: 200 within 250 ms again no later than 60 s after `rr_terminal_receipt` — the guarantee worth pinning — evidenced by the runner's `terminal_readyz recovered_ms=` line (probe every 2 s, fail-closed abort at the 60 s deadline) | CSV `readyz_code`, `readyz_ms` + `cycles.log` `rr_terminal refresh` marker and `terminal_readyz` line | Probed every sample, including during the terminal full-table re-send; the post-receipt probe loop pins the recovery bound. |
| Minimum sample count | ≥ 0.9 × (`SOAK_SECONDS` ÷ `SAMPLE_INTERVAL`) | CSV row count | One row per interval; scrape failures skip the row (and ≥ 5 consecutive failures abort). |
| No abort record | zero `ABORT:` lines | `cycles.log` | The runner writes one before any fail-closed exit (daemon death, blind sampler, disk floor, watchdog). |

## Failure-injection inventory

What each scenario actually injects (inventoried from the harness
scripts), mapped to the daemon guarantee it tests.

| Injection | Mechanism | Scenario(s) | Guarantee under test |
|-----------|-----------|-------------|----------------------|
| Peer daemon restart (session loss + GR) | `killall -9 bgpd` in FRR container (watchfrr restarts it, harness-supervised) | 1 | GR state machine: stale-mark, EoR, stale-clear, intern GC; bounded re-establish |
| Transactional config churn | `rbgp config plan`/`apply` cycles | 2 | Live-apply atomicity; zero session impact; no candidate-world leak |
| Controller route churn | gRPC AddPath/DeletePath | 3 | Injection path RIB + intern stability; exact announce/withdraw delivery |
| Route churn at scale (50 k) | tester bulk advertise + sustained churn | 4 | RIB/intern/label-set stability at scale |
| Kernel FDB churn (learn/age) | `bridge fdb add/del` | 5, 8 | Local-MAC observation → Type 2 ledger balance; retained-state plateau |
| Daemon process restart (orderly) | `pkill -TERM rustbgpd` in-container | 7, 8 | DF re-election, BUM-enforcement re-init, kernel-state reconcile after restart |
| Daemon crash (SIGKILL) | `KILL_MODE=kill` | 7, 8 (opt-in, non-default) | Same as above minus the orderly-drain mask |
| MAC mobility move | same MAC deleted on src PE, added on dst PE | 8 | RFC 7432 §15.1 sequence ratchet under concurrent ESI churn |
| Link carrier down/up | AC interface down/up | 6 | ES drain trigger, DF failover, recovery hold-off, bounded blackout |
| Tenant route add/del | `ip addr add/del` in VRF | 9 | L3 owned-state transactionality; route-wake path |
| SIGHUP policy-file reload at scale | engine copies next `.rpol` generation over the live file + real SIGHUP, every 30 min under churn | 10 | Signal-driven reload path: barrier-verified full-fleet re-advertisement, no session impact, no reload-cycle leak |
| Max-prefix trip + timed restart | designated member announces over its `max_prefixes` bound; daemon Cease teardown, hold-down, one timed restart; compliant re-announce | 10 | ADR-0108 enforcement + latch/restart cycle: exact breach accounting, countdown visibility, bounded recovery, headroom re-arm |
| Route churn at RR flagship scale | engine churners flap dedicated blocks every 125 ms across 1000 real iBGP RR-client sessions for 24 h, closed by a full-fleet ROUTE_REFRESH re-request | 11 | RFC 4456 reflection correctness under sustained churn: exact terminal Adj-RIB-Out delivery (99 900 non-self prefixes per observer), zero flaps, no RIB/intern leak |

### Coverage gaps — guarantees with NO soak injection

Listed explicitly so a window plan cannot mistake absence of red for
coverage:

1. **Daemon SIGKILL on the plain BGP/RR path.** Crash-style kills are
   exercised only inside the EVPN Gate 8b harness (and only when
   `KILL_MODE=kill` is set). Scenarios 1–3 never kill rustbgpd itself —
   the GR soak restarts the *peer*. Crash-recovery of the core BGP
   daemon (durable commit-confirm boot-revert included) has test
   coverage but no soak-duration injection.
2. **SIGHUP file-reload path.** ~~The daemon handles SIGHUP
   (`src/main.rs`), but the hot-reload soak drives only the gRPC
   transactional apply. The signal-driven reload path is unsoaked.~~
   **Closed by scenario 10**, which drives real SIGHUP policy-file
   reloads every 30 minutes at the 1000-peer flagship shape, each
   verified by the engine's completion barriers. (Config-file reload of
   *neighbor* shape via SIGHUP remains uncovered — scenario 10 reloads
   the policy file only.)
3. **Listener kill.** No scenario kills or wedges the gRPC listener or
   the Prometheus exporter mid-soak; listener-death behavior (audit
   continuity, reconnect handling) is untested at duration.
4. **RTR / RPKI cache withdrawal.** No soak exercises the rpki path at
   all — cache restart, serial desync, or mass VRP withdrawal under
   load are uncovered.
5. **Rapid peer flap storm.** The fastest failure cadence in the suite
   is one event per 90 s (scenario 6). Sub-minute repeated flaps
   (damping/pending-delete pressure) have bench coverage but no soak.
6. **Prefix-limit trip and timed restart.** ~~No soak drives a peer over
   a configured max-prefix bound and through the timed-restart cycle.~~
   **Closed by scenario 10**, which trips the designated member's
   aggregate `max_prefixes` bound every 4 hours and asserts the full
   breach → countdown → timed-restart → compliant-recovery evidence
   chain per cycle. (Per-family `max_prefixes_ipv4/ipv6` bounds and the
   failed-restart indefinite latch remain soak-uncovered — they have
   unit coverage only.)
7. **Transport-level disturbance.** No packet loss / latency / MTU
   churn (netem) injection anywhere in the suite.
8. **BMP / BFD subsystems.** No soak establishes a BMP station or BFD
   sessions; their long-run stability is uncovered.

A gap being listed here is not a commitment to close it — it is the
boundary of what a receipt from this suite can honestly claim.
