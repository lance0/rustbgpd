# IXP route-server receipt matrix — raw artifacts (2026-07)

Raw data behind [`../../ixp-matrix-2026-07.md`](../../ixp-matrix-2026-07.md):
the cross-daemon reload-stall matrix (rustbgpd `576c6c9b` vs BIRD 3.3.1
vs OpenBGPD 9.1) at 700 peers × 400,400 prefixes through the shared
`bench/scale/reloadstall` harness.

The four `rustbgpd/` cells were refreshed after the receipt's first
publication: the S3 re-announce plateau the receipt itself exposed was
root-caused (PeerUp initial-dump head-of-line blocking) and fixed at
`576c6c9b`, and all rustbgpd cells were rerun at that head (the S3
logs now also carry the harness's additive per-round `first_reann_s`
lines). The `bird/` and `openbgpd/` cells stand from the original
campaign at `40fd0a0c`, which is code-identical for them. See the
receipt's post-publication fix note.

## Layout

Four campaign legs × three cells, all `status = pass`:

| Leg | Scenario |
|---|---|
| `runA-s2/` | Run A: 4 policy reloads under live churn (S1 convergence = startup phase) |
| `runA-s3/` | Run A: flapstorm — 50 members hard-close/reconnect × 3 rounds |
| `runB-s2/` | Run B: independent repetition of S2 (fresh daemon starts) |
| `runB-s3/` | Run B: independent repetition of S3 |

Each cell (`rustbgpd/`, `bird/`, `openbgpd/`) contains:

- `reloadstall.log` — harness output: convergence lines, control
  window, per-reload percentile lines plus machine-readable
  `reloadstall_csv` rows (S2) or per-round `flapstorm_csv` rows (S3).
- `rss.csv` — external process-tree RSS samples (5 s cadence,
  `bench/scale/matrix/rss-sampler.sh`); the comparable memory
  instrument across all three daemons (OpenBGPD is 7 processes).
- `status` — the driver's pass/fail marker for the cell.
- `scenario/` — the generated daemon configs actually run
  (`config.toml` + `.rpol` generations, `bird.conf` + `gen*.conf`,
  `bgpd.conf` + `gen*.conf`).
- `daemon.log` / `daemon.log.gz` — the daemon's own log (gzipped where
  the raw file exceeds 1 MB; only the rustbgpd JSON logs do). The BIRD
  S3 logs are near-empty because BIRD logs reconfiguration, not
  steady-state session traffic, and S3 performs no reconfiguration.

## Not committed (campaign working state)

Preserved on the bench host under `bench/scale/matrix/`, referenced by
the receipt's honesty notes, and available on request:

- `artifacts-run*/rustbgpd-fail-rscontrol-oom/` — the aborted first
  rustbgpd attempts (100 GiB tree-RSS gate; the control-communities
  default regression the campaign caught).
- `artifacts-runB-s2/openbgpd-fail-rde-wedge/` — the OpenBGPD attempt
  that established 700 sessions but delivered zero prefixes for 120 s.
- `artifacts-bird-threads32/` — the BIRD `threads 32` sweep behind the
  threads-8 configuration decision.
- `artifacts-rung1/`, `artifacts-rung2/` — the 20×20k and 200×115k
  scale-ladder runs summarized in the receipt's ladder table.
- `artifacts-run*/rustbgpd-prefix475/` — the pre-fix rustbgpd cells
  from the receipt's first publication (the flat ~9.5–9.8 s S3
  re-announce plateau), preserved unmodified as the before-side of the
  post-publication fix note.

No host paths or identifiers appear in the committed files (verified by
scrub before staging; no substitutions were needed).
