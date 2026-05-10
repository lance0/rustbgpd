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
