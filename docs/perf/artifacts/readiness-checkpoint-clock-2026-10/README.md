# Readiness-checkpoint clock S2 A/B compact artifacts (2026-10-03)

These files are the evidence for the
[readiness-checkpoint clock S2 A/B](../../readiness-checkpoint-clock-2026-10.md).
They were assembled on 2026-10-10 from the campaign directory retained after
the 2026-10-03 run. All eight legs and all 32 reloads are included; nothing
was excluded or retried.

The campaign labels its two arms `main` and `fast`:

| Arm | Role | Source commit | Tree | Daemon SHA-256 |
|---|---|---|---|---|
| `main` | main before #2920 | `aae915bb49600a6711f2edecc6d374038ebe061a` | `c10d9494ee2a923d856664c31613b042b3f65dca` | `d99bdc7d0fec9ecfa2dacebb6b2ec7f5d3ed354a69490ed01095615a4ee9c874` |
| `fast` | #2920 head as measured | `5fedc3499cadf3e99c7996c8b8190a08fc3fd47e` | `e47fff14f512c2852c691783dc367855dff6a2f2` | `d2b1ac4c6ad49857fd2a642685fb2d687a7f02776e80a62dcc7f89837a895147` |

| Path | Contents |
|---|---|
| `matrix/matrix-{main,fast}-r{1,2,3,4}-s2/` | Matrix cells: `reloadstall.log`, `status`, `daemon.exit`, the two accepted host-quiet samples in `quiet.tsv`, 5-second process-tree and cgroup `rss.csv`, daemon `vmhwm`, the swap-fenced `cgroup-memory` readout, and runner `provenance.json` |
| `summary.csv` | Every headline value, one row per run, round and metric, as the campaign's [`summarize.py`](../../../../bench/scale/headline/summarize.py) wrote it |
| `report.md` | That run's per-arm table: range, median and count for every metric |
| `establishment-span.csv` | Per-leg span from the first to the 700th `session established` daemon log record |
| `rib-export-transition.csv` | One row per reload from the daemon log record "RIB export-policy transition completed": `leg`, `arm`, `run`, `reload`, `elapsed_ms`, `outcome` and `member_count` |
| `generation-phase.csv` | One row per reload: SIGHUP received to "config reload complete", the prestage round trip `elapsed_ms`, and the "reload generation phase timing" fields for prestage session apply, RIB transition, deferred refresh dispatch and generation total, converted from µs to ms |
| `extract_daemon_log.py` | The script that wrote the two daemon-log CSVs from the retained daemon logs |
| `recompute.py` | Checks coverage and identity, cross-checks the two CSVs against `summary.csv`, and recomputes every number the receipt quotes; exits 1 on a mismatch |
| `manifest.txt`, `identity.tsv`, `placement.txt` | Campaign shape, each arm's resolved commit, tree and binary hashes, and CPU affinity |
| `progress.txt` | Campaign log, with the load average, kernel swap counters and allowed CPUs at every leg boundary |
| `provenance.json` | Receipt-level summary: arms, trees, binary hashes, PR commits, shape, order, builds, toolchain and host class |

## Two RIB transition metrics

The daemon logs two different RIB transition durations per reload. The
receipt reports both, by these names:

- **RIB transition, peer-manager span.** `cohort_rib_transition_us` in the
  "reload generation phase timing" record: the peer manager's time from
  sending the cohort transition to the RIB manager until the reply. This is
  `daemon_rib_transition` in `summary.csv` and `cohort_rib_transition_ms` in
  `generation-phase.csv` (487.5–521.3 ms on `main`, 355.5–387.3 ms on `fast`).
- **RIB transition, RIB-manager record.** `elapsed_ms` in the "RIB
  export-policy transition completed" record: the RIB manager's own time
  from creating the transition to its commit, truncated to whole
  milliseconds. It is in `rib-export-transition.csv` only (487–512 ms on
  `main`, 355–381 ms on `fast`).

## Re-summarizing this bundle

`just bench-headline-summary <bundle> --out <dir>` (or
`python3 bench/scale/headline/summarize.py <bundle> --out <dir>`) accepts this
bundle, because the legs sit under `matrix/`. With the summarizer at the time
of publication, it reproduces every non-daemon row of `summary.csv` byte for
byte (120 rows). It does not reproduce:

- **The daemon reload rows** (`daemon_sighup_to_loaded`,
  `daemon_sighup_to_complete`, `daemon_validate`, `daemon_rib_transition`;
  128 rows) and `establishment-span.csv`. They come from the daemon logs,
  which are not in the bundle. `recompute.py` checks the SIGHUP-to-complete
  and RIB transition rows against `generation-phase.csv`, which was extracted
  from the same logs.
- **`report.md` as committed.** The summarizer's table format changed after
  this run (it now names each memory source and prints memory in whole KiB),
  and on a bundle it orders the arms differently, so the regenerated table
  differs in layout and number formatting, not in values.

## Notes

- **Local commits.** Each arm ran from a local, never-published commit with
  the arm's tree, parented on `aae915bb4`. The runner `provenance.json`
  files name those commits (`3c533ac809ee` for `main`, `bd7847212ee3` for
  `fast`); the tree hashes are the identity.
- **Measured head and merge.** #2920 merged as
  `ff666f7ecb57e3dba06fce824d65d428e73e3de1`. Its two commits after the
  measured head add a changelog fragment, and change only code compiled
  under `cfg(test)` or the non-default `bench-internals` feature, plus a
  unit test. The merge commit also includes main's test-only changes since
  `aae915bb4`. Neither the final head nor the merge commit was measured.
- **First invocation.** `progress.txt` begins with an earlier invocation at
  08:33 that built both arms and then had every leg's runner exit 75 within
  the same second, without a status file. 75 is the busy code of the shared
  host lock. No leg ran. The campaign was restarted into the same directory
  at 08:47 and reused the builds; the daemon hashes match.
- **Edits.** Files are copied unchanged except that `reloadstall.log` names
  the runner's fixed scenario directory as `<scenario-dir>/` instead of its
  absolute path. The full daemon logs, runner and build logs, scenario
  configurations and config-history snapshots remain outside the repository.
  An earlier private per-reload phase extraction in the same directory is not
  copied; `generation-phase.csv` reproduces all of its 192 per-reload values.

Check the bundle with `python3 recompute.py`.
