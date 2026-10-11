# Shared route-refresh evidence, 2026-10-11

Evidence for the [shared route-refresh A/B receipt](../../shared-route-refresh-2026-10-11.md).
All eight cells and 24 rounds are retained; no measured round was excluded.

- `raw/<arm>/k<K>/reloadstall.log` and `quiet.tsv`: complete harness output and
  accepted quiet-host samples, copied byte for byte.
- `summary.json`: all integer-clock derivations, per-requester coverage,
  readiness intervals, survivor gaps, RSS and matched round ratios.
- `native-exits.json`: recorded native exits and cleanup for the campaign and
  every cell, including absent owned processes and zero forced kills.
- `source-validation.json`: measured-source gates and ordinary source-hook outcomes,
  separate from later receipt-only edits. Original source log hashes are retained.
- `identity.json`, `toolchain.txt`: source and binary identities, input-refresh
  timestamps, source-inventory hashes, build outcomes and scope.
- `binaries/`: actual normal/build artifact closures and normalized dependency
  trees for both ordinary daemons. The only closure edit is replacing the
  absolute cache prefix in `cache_artifact` with `<CACHE>`; original capture
  hashes remain in `identity.json`. Numeric/configuration records are unchanged.
- `actual-feature-comparison.json`, `compare-arms.py`: the native build audit
  and its unchanged analyzer.
- `validate-control.py`: unchanged as-run raw-clock, exact-table, readiness,
  session, quiet-host and native-cleanup validator.
- `recompute.py`: replay of the published logs through that validator's
  unchanged `raw` and `quiet` functions, checking every native-exit receipt and
  reproducing `summary.json` exactly.
- `campaign.log`: native cell order and completion times.
- `cell.sh`: unchanged as-run cell procedure.
- `instrument.patch`: the common runner's complete instrument-only diff from
  its recorded base, covering refresh clocks, exact tables and readiness samples.

The summary's scope sentence was made publication-neutral; no numeric result
was changed. A private execution-session identifier was omitted from the native
exit receipt. The original summary hash is retained in `identity.json`.
Daemon logs, metrics dumps, scenario configurations and executable binaries are
not published. Live process/scenario absence was checked at acceptance time;
archival replay checks the recorded cleanup receipt and does not interpret a
later host's reused PIDs as the measured processes.

To reproduce all published round data and ratios:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 docs/perf/artifacts/shared-route-refresh-2026-10-11/recompute.py docs/perf/artifacts/shared-route-refresh-2026-10-11 > /tmp/shared-refresh-summary.json
```

The command exits zero and requires exact equality with the archived summary.
To reproduce the artifact-configuration audit without modifying the archive:

```bash
tmp=$(mktemp -d)
cp -r docs/perf/artifacts/shared-route-refresh-2026-10-11/. "$tmp"
python3 "$tmp/compare-arms.py" "$tmp"
diff docs/perf/artifacts/shared-route-refresh-2026-10-11/actual-feature-comparison.json "$tmp/actual-feature-comparison.json"
```

Both the comparison and diff exit zero. `SHA256SUMS` covers the published bundle.

`validation.txt` records successful recomputation plus rejected copies with a
wrong exact-table count, a failed quiet sample or a nonzero native metrics exit.
