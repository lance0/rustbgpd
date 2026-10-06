# Current-source IRR comparator artifacts — 2026-10-06

These files support the
[IRR 0% comparison receipt](../../irr-reload-current-comparators-2026-10-06.md):
unreleased rustbgpd `dcc9b6384`, BIRD 3.3.3 and OpenBGPD 9.3, with three
sequential roots and four reloads per daemon per root, 36 reload rows total.

| Path | Contents |
|---|---|
| `irr/irr-ov0-r{1,2,3}/` | Unedited root `COMPLETED`, `provenance.json`, headered `rows.csv` and dataset digest |
| Each daemon cell | Unedited headerless `rows.csv`, `status`, 5 s process-tree `rss.csv`, exact `memory-window` marker and native `cgroup-memory` or competitor `container-memory` readout |
| Native cells | Unedited `vmhwm`, `dataset-refresh-summary.csv`, `phase-timings.csv` and pre-reload `topology.json` |
| `summary.csv`, `report.md` | Queue extraction from `bench/scale/headline/summarize.py`; memory sources remain separate |
| `irr-cells.csv` | Queue extraction from the unchanged v0.74.0 bundle's `extract-tails.py`: per-reload completion and changed-observer gap, acceptance fields and sampled RSS for all three daemons |
| `identity.json` | Source/tree, four binary digests, workload inputs, comparator image identities and toolchain; runner exits come from `progress.txt` and the queue exit from `queue.exit` |
| `verification.json` | Completed cross-root verifier result: 36 rows, source identity and dataset digest; root paths use this bundle's relative layout |
| `progress.txt` | Queue repeat order and zero runner exits, followed by its completion marker |
| `queue.exit` | Unedited exit file from the completed queue process, recording zero |

Root CSVs retain separate `changed_maxgap_*` and
`all_observer_maxgap_*` fields. The latter extends through the slowest
changed observer and includes the trailing gap to that boundary; the
former ends at each changed observer's own completion and excludes a
trailing gap. Both include the leading gap from the reload trigger to the
first UPDATE. The two must not be substituted. A cell CSV has no header
and retains the same columns as the root CSV, including the leading
`cell` field.

Schema 3 readouts cover each fresh scope or container through harness
completion, before lifecycle probes or teardown. Every actual swap peak is
zero. The exact `memory-window` marker must be retained with its readout;
the peak is not restricted to the reload phase. Artifact `kB` labels mean
KiB. Native `cg_current`, process VmHWM and sampled RSS are separate readings.

## Re-extraction

From the repository root, writing into a fresh output directory:

```sh
python3 bench/scale/headline/summarize.py \
  docs/perf/artifacts/irr-reload-current-comparators-2026-10-06 --out <out>
python3 docs/perf/artifacts/cross-daemon-v0740-2026-10/extract-tails.py \
  docs/perf/artifacts/irr-reload-current-comparators-2026-10-06/irr <out>
```

The second command reproduces `irr-cells.csv` byte for byte. It also writes
a header-only `matrix-tails.csv`, because this campaign has no matrix cells;
that empty table is not included here. The first command reproduces the
non-daemon-log rows of `summary.csv`. Its 48 daemon-log timing rows and their
`report.md` ranges need the archived full native daemon logs, which are not
in this bundle. All-observer gap percentiles remain in the root `rows.csv`.

The bundle preserves the copied evidence byte for byte. Only
`verification.json` replaces raw absolute root paths with bundle-relative
paths; `identity.json` selects public identity fields from recorded
provenance and exit results. Full daemon and harness logs, configurations,
process/quiet evidence and topology scrapes remain outside the repository.
The saved verifier result records validation of those full roots; this
compact subset does not independently rerun `validate_root`.

Verify the bundle from this directory with `sha256sum -c SHA256SUMS`.
