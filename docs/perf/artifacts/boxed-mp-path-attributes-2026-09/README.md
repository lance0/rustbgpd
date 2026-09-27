# Boxed MP path-attribute payload artifacts

These are the retained artifacts for the
[boxed MP path-attribute receipt](../../boxed-mp-path-attributes-2026-09.md).
The base arm is `82700ff0dfe1b37d4e5a32ec1557e19a10abedab`; the head arm is
`aea6e2c77ee5581ff399fc27d6a8ebb816d2ea4d`.

## Contents

- `structural-results.csv`: every row of the full `compare-rib-memory.sh`
  campaign at 100k, 500k, and 900k prefixes.
- `codec-estimates.csv`, `export-probe-estimates.csv`,
  `parse-ipv6-estimates.csv`: the Criterion mean, median, and standard
  deviation in nanoseconds for every row, attempt, and arm of the three A/B
  runs.
- `codec-summary.md`, `export-probe-summary.md`, `parse-ipv6-summary.md`: the
  `compare-criterion.sh` verdict tables. Local output paths were removed; no
  value was changed.
- `allocation.jsonl`: the `codec-allocation-diagnostics` rows for both arms,
  with `arm` and `commit` fields added and keys sorted.
- `dhat-base.memory.tsv`, `dhat-head.memory.tsv`: DHAT owner summaries for
  the two daemon runs. The matching `*.dhat-derivative.tsv` files are the
  sanitized, bounded derivatives from which each summary regenerates. Raw
  DHAT JSON is intentionally absent.
- `dhat-base.csv`, `dhat-head.csv`, `release-{b1,c1,c2,b2}.csv`: sanitized
  bgperf2 result rows for the DHAT and release runs.
- `provenance.txt`: commits, commands, toolchain, and host class.
- `SHA256SUMS`: covers every file here except itself.

## Verification

```bash
sha256sum -c SHA256SUMS
for arm in base head; do
  python3 ../../../../bench/scale/rebaseline/classify_dhat.py \
    --from-derivative dhat-$arm.dhat-derivative.tsv \
    --check dhat-$arm.memory.tsv
done
for row in dhat-base dhat-head release-b1 release-c1 release-c2 release-b2; do
  python3 ../../../../bench/scale/rebaseline/sanitize_bgperf_csv.py \
    --from-sanitized $row.csv >/dev/null
done
```
