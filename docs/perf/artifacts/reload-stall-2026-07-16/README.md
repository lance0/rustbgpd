# Reload-stall campaign raw artifacts — 2026-07-16

Raw outputs of the accepted campaign behind the current numbers in
`docs/perf/reload-stall-2026-07.md` (commit measured: `a25ad76b`).
One directory per reload shape:

- `import-export/` — the historical full import+export policy swap.
- `export-only/` — the mixed export-only change (600/100 split
  disabled; all 700 members changed).

Per directory:

- `harness.out` — the reloadstall driver's full output: convergence,
  control window, per-reload percentiles (completion, max-gap,
  first-update), per-reload RSS, session health, and the durable
  `reloadstall_csv` records. Harness exit code appended.
- `probes.csv` — the concurrent health probe (50 ms loop timing
  `rbgp health` over the gRPC UDS): `epoch_seconds,latency_ms,exit`.
  Zero rows exceed the 200 ms readiness deadline in either shape.
- `daemon.log.gz` — the daemon's full JSON log for the campaign,
  including the four SIGHUP reload cycles and the clean SIGTERM exit.

Reproduction: `bench/scale/reloadstall/gen-scenario.py 700 <dir> <port>`
(append `700` for the export-only shape), release daemon on the
generated config, then
`reloadstall 700 400400 <port> <pid> member.rpol gen-a.rpol gen-b.rpol 4 30`
(append `700` for export-only). Regenerate the scenario before every
run — the harness overwrites the live policy file. Full method and
honesty notes live in the receipt document.
