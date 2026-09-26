# Headline refresh compact artifacts (2026-09-26)

These files retain the evidence behind the
[v0.72.0 and current-main headline refresh](../../headline-refresh-v0720-2026-09.md).

| Path | Contents |
|---|---|
| `matrix/matrix-{ctrl,cand}-r{1,2,3}-{s2,s3}/` | Per-cell `reloadstall.log`, `status`, 5-second process-tree `rss.csv`, daemon `vmhwm`, and runner `provenance.json` |
| `irr/irr-ov0-{ctrl,cand}-r{1,2,3}/` | IRR root `COMPLETED`, `rows.csv`, `provenance.json`, dataset digest, and the rustbgpd cell's `reloadstall.log`, `rss.csv`, `status`, and dataset-refresh summary |
| `rr1000/rr1000-{ctrl,cand}-c{1,2}/` | Campaign `COMPLETED` plus each attempt's `phase.json`, `provenance.json`, and `rss.json` |
| `progress.txt` | Campaign driver log, with the load average and kernel swap counters at every run boundary |
| `summary.csv` | Every value the receipt reports, one row per run, round, and metric |
| `establishment-span.csv` | Per-leg span from the first to the 700th `session established` daemon log record, derived from the daemon logs |

`ctrl` is the v0.72.0 release tree (tree `4ff22f7e882d5ade6057eacbe1e7da5613955838`),
run from a local commit whose only purpose was to satisfy the IRR runner's
source gate. `cand` is main at `33f8e7142c4a984812de0ba927b65a842a4db62c`.

The IRR `provenance.json` files record hashes for every binary the runner
builds. Only `target/release/rustbgpd` is the measured identity:
`149f07de…` for v0.72.0 and `0bf3866a…` for main. `rbgp` differs between the
arms because its source differs, and it is not used by a `rustbgpd-sighup`
root. `rs-config-render` is identical in both arms. `reloadstall` differs only
through the `crates/wire` capability change disclosed in the receipt.

Local paths are replaced with `<run-root>`, `<control-tree>`, and
`<candidate-tree>`. Full daemon logs, scenario configurations, and metrics
scrapes remain outside the repository.

Verify the bundle with `sha256sum -c SHA256SUMS`.
