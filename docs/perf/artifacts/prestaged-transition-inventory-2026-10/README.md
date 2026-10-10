# Prestaged transition inventory A/B extracts

Compact evidence for the
[October 2026 prestaged transition inventory receipt](../../prestaged-transition-inventory-2026-10.md).
All six process legs and all 24 reloads are retained; no leg or reload was
excluded or retried. Both arms are **instrumented** builds: each carries
`instrumentation.diff`, which is not part of #2930 or of main.

| File | Contents |
| --- | --- |
| `reloads.csv` | One row per reload (6 legs × 4). Leg, run order, arm and reload number; daemon log values for that reload (SIGHUP timestamp, `cohort destination prestage round trip` `elapsed_ms` and `prestaged`, `RIB export-policy transition completed` `elapsed_ms`/`outcome`/`member_count`, and three fields of `reload generation phase timing`); every field of the harness's native `reloadstall_csv` row unchanged; and the median, minimum and maximum over the 700 observers of base-prefix UPDATEs received between SIGHUP and completion (from the instrumented harness's `scout_gap` lines). |
| `transition-polls.csv` | Every `scout transition poll` line from the six daemon logs (318 rows): leg, arm, reload, timestamp (poll end), phase, `poll_us`, terminal flag and primary backlog. The fence span and BuildInventory time are derived from these rows. |
| `legs.csv` | One row per leg: status and daemon exit, base commit and dirty flag, daemon and harness sha256, native workload inputs, the two host-quiet samples (load, quiet verdict, swap counters unchanged), approximate VmHWM, kernel cgroup peak and the swap limit. |
| `recompute.py` | Validates coverage, run order and arm identity, derives every quoted metric from the three CSVs, prints the A/B table and exits non-zero on any mismatch with the values quoted in the receipt, the #2930 PR-body table or the CHANGELOG rounding. |
| `abtable-output.txt` | The original table output produced on the measurement day by the local analysis script whose logic `recompute.py` reimplements. |
| `instrumentation.diff` | Local instrumentation applied to both arms: the per-poll phase log line in the RIB transition loop and the per-observer `scout_gap` line in the `reloadstall` harness. |
| `fix.diff` | The change applied to the fix arm. It is byte-identical to `git diff 65aa92cc0 18b6c81fe -- crates/`, the first commit of #2930. |
| `scan-microbench.txt` | Output of one local single-core microbenchmark run used in the #2930 PR body to attribute the remaining fenced time. Its test is not in the repository and it is not part of this A/B. |
| `drivers/` | The wrapper scripts and their logs as recorded (`go.sh`, `run-ab.sh`, `run-leg.sh`, `build-arm.sh`, `ab.log`, build logs and per-leg runner logs). Private paths are replaced with `<bench-dir>`, `<host-lock>`, `<worktree>-ARM` and `<scenario-dir>`; nothing else was changed. |
| `provenance.json` | Arms, base commit/tree, reconstructed source trees, daemon/harness digests, build commands, toolchain, kernel, host class, workload, run order and deviations from the native runner. The raw directory (139 files: full daemon and harness logs, scenario, runner records) is not published. |

## Derivations

- **Fence span**: from the start of the reload's first poll (`classify`; poll
  end minus `poll_us`) to the end of its terminal `commit_members` poll.
- **BuildInventory busy**: the sum of `poll_us` over that reload's
  `build_inventory` polls. Main walks the inventory in several budgeted polls
  under the fence; the fix arm re-checks the prestaged walk in one poll.
- **Stall**: the harness's `changed_maxgap_*` fields. For each observer, the
  largest gap from SIGHUP to its first UPDATE or between consecutive UPDATEs,
  up to that observer's completion (every base prefix seen with the new
  generation marker); p50, p95 and maximum are over the 700 observers. All 700 peers
  are changed peers in this shape, so the all-observer fields are identical.
- **Medians**: pooled over the 12 reloads per arm. The four reloads in one
  process are correlated; the three legs per arm are the independent launches.

The #2930 PR-body table read the stall and completion values from the
harness's two-decimal summary lines. `recompute.py` reports the native CSV
precision and separately reproduces the PR-body cells after the same rounding.

## Reproduce

From the repository root:

```bash
python3 docs/perf/artifacts/prestaged-transition-inventory-2026-10/recompute.py
```

To rebuild the measured source trees, check out `65aa92cc0` and apply
`instrumentation.diff` (main arm) or `fix.diff` then `instrumentation.diff`
(fix arm). The main-arm reconstruction reproduces the recorded fingerprint of
that worktree's uncommitted diff; the fix-arm reconstruction does not (see
`provenance.json`), so the daemon digest is the binding identity for that arm.
