# M33 24-Hour Soak Harness

Long-running variant of `tests/interop/scripts/test-m33-evpn-scale.sh` that
sustains 50,000 EVPN Type 2 routes plus continuous churn for `SOAK_HOURS`
hours and asserts no memory leak, no session flaps, no metric drift.
Reuses the M33 topology and binaries exactly — no Rust code changes.

The point: M33 itself runs for ~3 minutes. That's enough to gate "the RR
reflects 50k routes," but not enough to detect slow leaks in the attribute
intern table, the secondary prefix index, the per-peer Prometheus label
set, or anywhere else state can quietly accumulate. A clean 24-hour soak
is a v1.0 prerequisite for honestly claiming "no leaks under sustained
churn."

## Run

```bash
docker build -t rustbgpd:dev .
containerlab deploy -t tests/interop/m33-evpn-scale.clab.yml

# Full 24h run (default):
bash tests/soak/run-m33-soak.sh

# Smoke test (1h, 30s sample cadence, 5-min warmup):
SOAK_HOURS=1 SAMPLE_INTERVAL=30 WARMUP_SEC=300 \
    bash tests/soak/run-m33-soak.sh

# Auto-destroy the topology on exit (success, fail, or CTRL-C):
CLEANUP=1 bash tests/soak/run-m33-soak.sh
```

The runner expects to be invoked from the repo root (the shared
`test-lib.sh` preflight checks for `proto/rustbgpd.proto` relative
to the current working directory).

## Output

Each run creates `tests/soak/runs/<UTC-timestamp>/` containing:

| File | Content |
|------|---------|
| `samples.csv` | One row per sample interval (timestamp, uptime, RSS, CPU, gRPC health, EVPN RIB sizes, flap/drop/message counters) |
| `soak.log` | Mirrored stdout/stderr from the runner |
| `monitor.json` | Final report from the synthetic observer peer |
| `monitor.log` | Tracing logs from the observer peer |
| `report.json` | Analyzer verdict (slope, percentiles, gates, failure list) |
| `run.json` | Run metadata: image SHA, git rev, env vars at start |

The runner exits non-zero if the analyzer fails any gate.
`tests/soak/runs/` is gitignored — runs stay local to the host.

## Gates

| Gate | Default threshold |
|------|-------------------|
| Memory slope (steady state, MB/hour) | `< 1.0` fail; `< 0.5` clean |
| Peak resident memory (MB) | `< 512` |
| Session flap delta | `== 0` |
| Outbound route drop delta | `== 0` |
| gRPC health failures | `0` across all samples |
| Daemon unhealthy at end (last 3 samples) | false |
| Process restart detected (counter monotonicity) | false |

Verdicts: `clean` (slope < 0.5 MB/h and all gates pass), `pass` (gates pass
but slope between 0.5 and 1.0 MB/h), `fail` (any gate breached).

Gate thresholds are CLI-overridable on the analyzer:
`--slope-fail-mb-per-hour`, `--slope-clean-mb-per-hour`, `--mem-max-fail-mb`.

## Configurable env vars

| Variable | Default | Purpose |
|----------|---------|---------|
| `SOAK_HOURS` | `24` | Total soak duration |
| `WARMUP_SEC` | `600` | Skip the first N seconds from the regression |
| `SAMPLE_INTERVAL` | `60` | Seconds between samples |
| `HEALTH_CHECK_INTERVAL` | `300` | Seconds between gRPC health checks (two consecutive failures abort) |
| `COUNT_PER_TESTER` | `25000` | Routes per tester (50k total) |
| `ADVERTISE_RATE` | `5000` | Bulk-advertise rate per tester |
| `CHURN_RATE` | `1000` | Churn rate per tester (rps) |
| `TESTER_LINGER_SEC` | `120` | Tester linger after churn ends |
| `CONVERGE_TIMEOUT` | `120` | Initial convergence deadline |
| `CLEANUP` | `0` | Set to `1` to `containerlab destroy` on exit |

## Methodology notes

**Memory measurement.** "Memory" is the container's cgroup working-set RSS
as reported by `docker stats`, which excludes reclaimable page cache. This
is the right proxy for application-level leaks. We do not add an in-process
`process_resident_memory` Prometheus gauge — `docker stats` is parity with
M33's existing measurement source, and adding a runtime gauge for one rare
consumer would be over-engineering.

**Warmup window.** The first 10 minutes are skipped from the regression by
default. That window covers bulk advertise (5s × 2 testers) plus initial
convergence and the allocator settling at its steady-state working set.
Including it in the regression would compress the slope toward zero and
hide late-stage drift.

**Restart detection.** If `bgp_messages_sent_total` ever decreases between
consecutive samples, the daemon process restarted. That invalidates the
soak (the regression would show a flat or negative slope and silently hide
a leak), so the analyzer force-fails and the run must be re-done.

**Resume after host reboot.** Not supported. The CSV is written
incrementally so a partial file is salvageable for diagnostics, but the
analyzer should not stitch two halves — it would silently re-introduce a
warmup window in the middle. If the host reboots mid-soak, rerun from
scratch.

**Suspicious linear slope on a known-clean build.** Confirm by reading the
container's cgroup memory accounting separately:

```bash
docker exec clab-m33-evpn-scale-rustbgpd \
    cat /sys/fs/cgroup/memory.stat 2>/dev/null \
    || docker exec clab-m33-evpn-scale-rustbgpd \
       cat /sys/fs/cgroup/memory/memory.stat
```

`rss` is the application working set. `cache` is reclaimable page cache.
`kernel` (or `kmem`) is kernel memory, which most kernels do not include
in `memory.usage`. If `rss` is flat but `docker stats` reports growth,
the growth is in cache or kmem and is not an application leak.

## What this harness is NOT

- Not in CI. Runs manually. Run twice manually before tagging 1.0.
- No SQLite/database. One CSV per run; the directory is the audit trail.
- No live dashboard, no alerting, no notification.
- No multi-host coordination. Single host, single soak at a time.
- No `--repeat` mode. The tester/monitor binaries run once per soak with
  durations scaled up to cover the full window.

## When to run

- **Before every minor-version tag** (e.g., before 0.10.0, 1.0.0).
- **After any significant change to RIB internals** (intern table,
  prefix index, distribution hot path, GR/LLGR sweep paths).
- **After dependency bumps** (tokio major, hashbrown / smallvec major)
  that could shift allocator behavior.
- **Before declaring a deployment "production-ready"** for a real
  operator.

## Failure-mode validation (optional)

To confirm the harness's gates actually trip:

- `docker kill clab-m33-evpn-scale-rustbgpd` mid-soak → expect
  `daemon_unhealthy_at_end: true` and a `fail` verdict from the
  analyzer (or, if the kill happens before the health check fires, the
  outer wait loop should abort within 2 × `HEALTH_CHECK_INTERVAL`).

- Build a debug daemon with an artificial leak (e.g., `Box::leak` in a
  hot path), run a 1-hour soak, expect `slope_mb_per_hour > 1.0` and
  `fail` verdict.

---

# Gate 8b 24-Hour Soak

Sibling harness covering the Gate 8b multi-homing enforcement
path — the actual `apply_bum_enforcement = true` kernel-mutation
behavior under sustained DF-flip + candidate-set-recompute churn.

The M33 soak above leaves `apply_bum_enforcement = false` because
M33 has no segments configured. Gate 8b needs its own harness so
the BUM-suppression rtnetlink path is exercised on every flip.

## Topology

`tests/soak/gate8b-soak.clab.yml` deploys 2 rustbgpd PEs
(`clab-gate8b-soak-pe1` / `pe2`) with:

- shared ESI `00:00:00:00:00:00:00:00:00:01` for VNI 100,
- `apply_bum_enforcement = true` on both,
- full kernel topology per PE (br100 + vxlan100 + ce100a/b veth)
  so the BUM-suppression filter has a real CE-facing port to
  flip flags on,
- iBGP L2VPN/EVPN session between PE1 (10.0.0.1) and PE2
  (10.0.0.2).

## Run

```bash
docker build -t rustbgpd:dev .
sudo containerlab deploy -t tests/soak/gate8b-soak.clab.yml

# Full 24h run (default):
bash tests/soak/run-gate8b-soak.sh

# 1h smoke with 5-min flip cadence:
SOAK_HOURS=1 FLIP_INTERVAL_SEC=300 \
    bash tests/soak/run-gate8b-soak.sh

# Auto-destroy on exit:
CLEANUP=1 bash tests/soak/run-gate8b-soak.sh
```

## What gets sampled

`tests/soak/runs/gate8b-<UTC>/samples.csv`, one row per
`SAMPLE_INTERVAL` (default 60s):

```
ts_unix, elapsed_sec,
pe1_rss_mb, pe2_rss_mb,
pe1_df_role, pe2_df_role,
pe1_df_changes, pe2_df_changes,
pe1_bum_flags, pe2_bum_flags,    # df / nondf / mixed / unreachable
pe2_running                       # 1 / 0 driven by harness
```

Plus per-PE daemon logs streamed to `pe1.log` / `pe2.log` and
flip events recorded in `flips.log` so post-mortem of any anomaly
correlates the harness action to whatever the daemon was doing.

## Live monitoring

```bash
tail -F tests/soak/runs/gate8b-<UTC>/soak.log     # harness progress
tail -F tests/soak/runs/gate8b-<UTC>/samples.csv  # CSV stream
tail -F tests/soak/runs/gate8b-<UTC>/pe1.log      # daemon log
tail -F tests/soak/runs/gate8b-<UTC>/flips.log    # flip events
```

## Analyze

```bash
python3 tests/soak/analyze-gate8b-soak.py \
    tests/soak/runs/gate8b-<UTC>/samples.csv \
    --output tests/soak/runs/gate8b-<UTC>/report.json
```

Gates: per-PE memory slope < 1.5 MB/h, peak RSS < 512 MB, DF
transition counters monotone (no daemon restart inside the
window), at least one full flip cycle observed.

## When to run Gate 8b soak

- **Before flipping the `apply_bum_enforcement` default to `true`**
  (currently `false` for safety).
- **After any change to** `crates/evpn/src/df_election.rs`,
  `crates/evpn/src/origination_es.rs`, `src/evpn_segment.rs`,
  `src/evpn_dataplane.rs`, `crates/evpn-linux/src/bum_filter.rs`,
  `crates/evpn-linux/src/linux/bum_filter.rs`, or
  `crates/evpn-linux/src/reconcile.rs`.
- **Before tagging the first release that ships Gate 8b
  enforcement on by default.**

---

# Gate 8b MAC-churn 24-Hour Soak

Sibling to the Gate 8b BUM-state soak above. Same 2-PE topology,
same DF flips, but with sustained bridge-FDB churn injected on top
so the soak exercises:

- kernel-learn / local-MAC observation → Type 2 origination
- ADR-0059 receive-side aliasing-ECMP (FDB nexthop groups)
- RFC 7432 §15.1 MAC mobility sequencing
- Gate 8b BUM-suppression while FDB programming is in flight
- the ADR-0059 drift-recovery counters under realistic timing

The base Gate 8b soak validated steady memory under DF-flip churn
only (no FDB churn). This variant is the alpha-checklist exit
condition for relaxing `apply_bum_enforcement` and
`apply_aliasing_ecmp` to production defaults.

## Topology

Reuses `tests/soak/gate8b-soak.clab.yml` unchanged. Same PE
container names (`clab-gate8b-soak-pe1` / `pe2`), same shared ESI,
same VNI 100. The harness mutates the bridge FDB via
`docker exec <pe> bridge fdb add/del <mac> dev ce100a master static`
— direct kernel mutation so the daemon's local-MAC observation
pipeline is the path under test, not the gRPC route-inject path.

## Run

```bash
docker build -t rustbgpd:dev .
sudo containerlab deploy -t tests/soak/gate8b-soak.clab.yml

# Full 24h run (default):
bash tests/soak/run-gate8b-mac-churn-soak.sh

# 1h smoke with tighter churn:
SOAK_HOURS=1 CHURN_INTERVAL_SEC=2 CHURN_BATCH_SIZE=32 \
    bash tests/soak/run-gate8b-mac-churn-soak.sh

# 6-minute aggressive stress (~25 ops/sec, useful pre-1h):
SOAK_HOURS=0.1 CHURN_INTERVAL_SEC=2 CHURN_BATCH_SIZE=50 \
    bash tests/soak/run-gate8b-mac-churn-soak.sh

# Auto-destroy on exit:
CLEANUP=1 bash tests/soak/run-gate8b-mac-churn-soak.sh
```

## Churn pattern

A bounded rotating MAC pool. The harness picks one batch action
per tick (`CHURN_INTERVAL_SEC`, default 5s):

- **Add**: install `CHURN_BATCH_SIZE` new MACs on a PE via
  `bridge fdb add`. Daemon classifies them as local and originates
  Type 2.
- **Delete**: remove `CHURN_BATCH_SIZE` MACs from a PE via
  `bridge fdb del`. Daemon withdraws the Type 2.
- **Mobility**: pick MACs on one PE, delete from src and add on
  dst using the same MAC address. Triggers RFC 7432 §15.1 mobility
  sequencing on the peer PE while ADR-0059 FDB-NHG construction is
  also under sustained shared-ESI churn.

Pool size is bounded (`MAC_POOL_SIZE`, default 512). Per-PE
occupancy bracketed by `[POOL_MIN, POOL_MAX]` around
`MAC_POOL_SIZE / 2`; the harness forces grow/shrink when the
brackets are crossed so the soak doesn't drift into an empty or
saturated state.

DF flips continue concurrently. The flip mechanism is **process
restart** (`pkill -TERM rustbgpd` inside the container, then re-
launch via `start-rustbgpd-soak-gate8b.sh`), not container
restart. Container restart via `docker stop` / `docker start`
tears down the clab-managed `eth1` veth pair on both sides,
which destroys the 10.0.0.x point-to-point and makes post-flip
BGP re-establishment impossible — process restart preserves the
netns, the veth, the bridge, the VXLAN port, and the kernel FDB
rows. The harness's `verify_topology_link` helper asserts the
eth1 + 10.0.0.x address is present on both PEs **before AND
after every flip**, and fails loud with `exit 4` if it's gone
(also runs once at warmup as a fresh-deploy sanity check).
Set `KILL_MODE=kill` to send `SIGKILL` instead — a crash-style
flip useful for catching paths the orderly-drain path masks.

> ⚠️ **Do not regress to `docker stop` / `docker start` as the
> flip mechanism.** The clab veth lives in both containers' netns;
> destroying one side's netns destroys the veth on both sides, the
> clab `exec:` block does NOT re-run on `docker start`, and BGP
> can never re-establish on the same 10.0.0.x point-to-point. This
> showed up in the first 1h soak attempt as a daemon-side
> `idle → connect → SYN-SENT` wedge — actually a topology-lost
> false positive. The `verify_topology_link` post-flip guard is
> the regression tripwire for this exact failure mode.

## What gets sampled

`tests/soak/runs/gate8b-mac-churn-<UTC>/samples.csv`, one row per
`SAMPLE_INTERVAL` (default 60s):

```
ts_unix, elapsed_sec,
pe1_rss_mb, pe2_rss_mb,
pe1_df_role, pe2_df_role,
pe1_df_changes, pe2_df_changes,
pe1_bum_flags, pe2_bum_flags,
pe2_running,
pe1_established_seen, pe2_established_seen,         # sum of bgp_session_established_total — per-sample observability after the pre-churn gate
pe1_pool_size, pe2_pool_size,                       # harness-tracked
pe1_fdb_total, pe2_fdb_total,                       # kernel `bridge fdb show | wc -l`
pe1_fdb_extern_learn, pe2_fdb_extern_learn,         # daemon-programmed remote rows
pe1_nh_count, pe2_nh_count,                         # `ip nexthop show | wc -l` — ADR-0059
pe1_local_origs, pe2_local_origs,                   # evpn_local_originations_total
pe1_local_orig_errors, pe2_local_orig_errors,
pe1_local_obs_drops, pe2_local_obs_drops,
pe1_dup_mac_moves, pe2_dup_mac_moves,               # RFC 7432 §15.1
pe1_drift_members_repaired, pe2_drift_members_repaired,
pe1_drift_groups_replaced, pe2_drift_groups_replaced,
pe1_drift_orphans_cleaned, pe2_drift_orphans_cleaned,
pe1_drift_disabled, pe2_drift_disabled,             # ADR-0059 drift counters
churn_adds_total, churn_dels_total, churn_moves_total
```

Plus per-PE daemon logs (`pe1.log` / `pe2.log`), flip events
(`flips.log`), churn batches (`churn.log`), and live pool state
under `state/`.

## Live monitoring

```bash
tail -F tests/soak/runs/gate8b-mac-churn-<UTC>/soak.log
tail -F tests/soak/runs/gate8b-mac-churn-<UTC>/samples.csv
tail -F tests/soak/runs/gate8b-mac-churn-<UTC>/churn.log
tail -F tests/soak/runs/gate8b-mac-churn-<UTC>/flips.log
```

## Analyze

No dedicated analyzer yet — `tests/soak/analyze-gate8b-soak.py`
covers the BUM-state gates that still apply (memory slope, peak
RSS, DF transition monotonicity). MAC-churn-specific gates
(`evpn_local_origination_errors_total == 0`, `extern_learn` count
stable around the pool target on the receiver, ADR-0059 drift
counters non-monotone but bounded) currently surface from manual
CSV inspection.

## When to run

- **Before flipping `apply_bum_enforcement` and/or
  `apply_aliasing_ecmp` to production defaults** — this is the
  alpha-checklist exit condition (`docs/evpn-alpha-soak.md`,
  "remaining multi-homing enforcement work").
- **After any change to** the local-MAC origination / withdraw
  path (`crates/evpn-linux/src/reconcile.rs`,
  `src/evpn_originator.rs`,
  `src/evpn_dataplane.rs`) or the ADR-0059 receive-side aliasing
  / drift-recovery path (`crates/evpn-linux/src/diff.rs`,
  `crates/evpn-linux/src/linux/nexthop_raw/`).
- **Before tagging the first release that flips either default.**

## Smoke-before-soak

Soak-before-soak discipline: always run the short stress before
committing 24 hours of wall clock.

```bash
# 5-10 minute aggressive stress — catches obvious leaks, FDB-NHG
# construction failures, or daemon hangs under load.
SOAK_HOURS=0.1 CHURN_INTERVAL_SEC=2 CHURN_BATCH_SIZE=50 \
    bash tests/soak/run-gate8b-mac-churn-soak.sh

# 1h soak — catches non-obvious slow drift.
SOAK_HOURS=1 bash tests/soak/run-gate8b-mac-churn-soak.sh

# Only then kick the 24h.
bash tests/soak/run-gate8b-mac-churn-soak.sh
```

---

# Gate 9 slice 6 24-Hour Soak

Symmetric Interface-less IRB / Type 5 churn harness. The first
Gate 9 soak: validates the transactional `L3OwnedState` model and
the `RTNLGRP_IPV4_ROUTE` wake path under sustained tenant-prefix
churn against a stable FRR peer.

## Topology

`tests/soak/gate9-slice6-soak.clab.yml` deploys 2 PEs
(`clab-gate9-slice6-soak-pe1` / `pe2`) reusing M39's config +
scripts so the soak shape matches the smoke shape:

- PE1 = rustbgpd (`rustbgpd:dev`) at 10.0.0.1, vrf1/L3VNI 100,
  L3VXLAN enslaved directly to the VRF (Interface-less),
  operator-supplied Router MAC `02:00:00:00:01:01`.
- PE2 = FRR 10.3.1 at 10.0.0.2, vrf1/L3VNI 100, tenant
  `198.51.100.0/24` advertised steady-state via
  `advertise ipv4 unicast`.
- Direct iBGP L2VPN/EVPN session between the two PEs.

## Churn pattern

The driver cycles PE1's tenant `192.0.2.1/24` on `lo-vrf1`:

1. **At start**: tenant is UP (provisioned by the script before
   the daemon launches so slice 6a's first observation pass sees
   it).
2. **Every `CHURN_INTERVAL_SEC`** (default 30 s): flip — `ip addr
   del` when UP, `ip addr add` when DOWN. Each up→down transition
   exercises the slice 6a `RTM_DELROUTE` wake → slice 6b Type 5
   withdraw → FRR drops the route. Each down→up transition
   exercises the slice 6a `RTM_NEWROUTE` wake → slice 6b Type 5
   announce → FRR re-imports.

Default 30 s churn × 24 h = 2880 add/del transitions ≈ 1440 full
churn cycles. PE2's side stays steady — slice 6c's `L3OwnedState`
keeps PE2's `198.51.100.0/24` installed the whole soak, so
import-side drift would show up as installed_routes_count
oscillation rather than steady state.

## Run

```bash
docker build -t rustbgpd:dev .
sudo containerlab deploy -t tests/soak/gate9-slice6-soak.clab.yml

# Full 24h run (default):
bash tests/soak/run-gate9-slice6-soak.sh

# 1h smoke with tighter 15 s churn:
SOAK_HOURS=1 CHURN_INTERVAL_SEC=15 \
    bash tests/soak/run-gate9-slice6-soak.sh

# Auto-destroy on exit:
CLEANUP=1 bash tests/soak/run-gate9-slice6-soak.sh
```

## What gets sampled

`tests/soak/runs/gate9-slice6-<UTC>/samples.csv`, one row per
`SAMPLE_INTERVAL` (default 60 s):

```
ts_unix, elapsed_sec,
pe1_rss_mb, pe2_rss_mb,
pe1_installed_routes,      # gauge — should sit at 1 (PE2 steady)
pe1_observed_routes,       # gauge — oscillates 0/1 with churn
bgp_established,           # 1/0 from PE2's vtysh view
tenant_present,            # 1/0 — matches harness churn state
churn_cycles               # cumulative add→del→add cycle count
```

The originated-route count is currently surfaced via gRPC
(`IpVrfState.originated_routes_count`) rather than Prometheus, so
the CSV doesn't carry it. `pe1_observed_routes` is the upstream
input to slice 6b origination (the kernel route the observer kept
after the slice 6a classifier), so it tracks the churn cadence
one reconcile-pass behind the harness `ip addr add/del` and is a
sufficient proxy for "did the originator see something to act on".

Plus per-PE daemon logs streamed to `pe1.log` / `pe2.log` and
per-cycle events recorded in `churn.log`.

## Gates

- **Memory slope** (PE1, PE2) < 1 MB/h over the post-warmup
  window. RSS in steady state should plateau within the first
  few hours; sustained growth signals a leak in the L3 ownership
  model or the wake path.
- **Peak RSS** < 400 MB. The M39 smoke baseline is ~14 MB, so the
  budget is generous; sustained growth toward the cap is the
  failure mode to catch.
- **`bgp_established == 1`** on every sample after warmup. Any
  session flap is a regression (the BGP/TCP stack isn't supposed
  to care about Type 5 churn).
- **`pe1_installed_routes == 1`** on every sample after warmup
  (PE2's steady advertisement should stay imported).
- **`tenant_present` ↔ `pe1_observed_routes`** must agree on
  every sample after the next-reconcile latency budget
  (origination follows observation directly; if observed lags
  the harness's `ip addr add/del` for more than a sample
  interval, the wake path or the observer has a regression).
- **`churn_cycles` strictly monotone** across the run. The driver
  never goes backwards; a non-monotone column means the script
  crashed and a restart resumed mid-run.

## When to run Gate 9 slice 6 soak

- **Before flipping any Gate 9 dataplane primitive default**
  (none today — but follows the same gate as Gate 8b).
- **After any change to** `crates/evpn/src/ip_vrf/`,
  `crates/evpn-linux/src/l3_diff.rs`,
  `crates/evpn-linux/src/linux/l3.rs`,
  `crates/evpn-linux/src/linux/routes.rs`,
  `crates/evpn-linux/src/linux/notify.rs` (route classifier),
  or the `evpn_l3_originator` / `evpn_l3_installer` daemon tasks.
- **Before tagging any release that touches the symmetric IRB
  packet path or the L3 owned-state model.**
