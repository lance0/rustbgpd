# Route-refresh readiness compact artifacts (2026-10-10)

These files are the evidence for the
[route-refresh replay readiness A/B](../../route-refresh-readiness-2026-10.md).

| Path | Contents |
|---|---|
| `cells/{base,fix}-k1-rep{1..4}/reloadstall.log` | Harness output for each cell, with its `converged_rejoin_csv` rows and, for a failing cell, the `FAIL:` line |
| `cells/*/cell.log` | Cell start and end, with the harness and daemon exit codes |
| `cells/*/quiet.tsv` | The two accepted quiet-host samples taken before the cell |
| `daemon-events.csv` | Every `handling route refresh request` and `readiness probe failed` event, extracted from each cell's daemon log |
| `cell.sh` | The per-cell procedure. Local directories are replaced with `<bench-dir>` and `<cell-dir>` |
| `provenance.json` | Arms, daemon hashes, instrument, shape, CPU placement and cell order |
| `recompute.py` | Recomputes the receipt's table and survivor-gap range from these files, and exits non-zero on any mismatch |
