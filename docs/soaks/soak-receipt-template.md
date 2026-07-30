# Soak Receipt — <scenario name> <duration>

Copy this template for every soak run — **pass, fail, or aborted**. A
red receipt is published with the same completeness as a green one.
Gates and bounds come from `docs/soaks/soak-acceptance-gates.md` at the
run's git SHA; they are quoted here, never invented here.

Host-shape rule: CPU model, core count, and RAM only. Never hostnames,
usernames, home paths, or network names — scrub them from any pasted
command output.

**Status:** <In progress | Complete — verdict: **PASS** | Complete —
verdict: **FAIL** | **ABORTED**>
**Run ID:** `tests/soak/runs/<run-dir-name>`
**Daemon version:** <vX.Y.Z or "unreleased"> at git SHA `<sha>`
(image `rustbgpd:dev` built from this SHA: <yes/no — if no, state the
image's SHA>)
**Scenario config hash:** `<sha256 of run.json>` (pins duration,
cadence, pool sizes, topology, and container names as executed)
**Date:** <start UTC> → <end UTC> (<actual duration>)

## Verdict

**<PASS | FAIL | ABORTED>.** <One paragraph: the headline numbers and,
for FAIL/ABORTED, the failed gate(s) or abort trigger in plain words.>

## Run shape

| Field | Value |
|-------|-------|
| Scenario | <name + one-line description> |
| Harness | `tests/soak/<runner>.sh` |
| Analyzer | `tests/soak/<analyzer>.py` |
| Topology | `tests/soak/<topology>.clab.yml` |
| Host shape | <CPU model>, <N> cores, <M> GB RAM |
| Duration | target <T> s, actual <T'> s |
| Sample interval | <N> s |
| Injection cadence | <e.g. peer restart every 300 s> |
| Warmup excluded from slopes | <N> s |
| Total data samples | <N> |

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| <e.g. peer daemon restart> | <expected count> | <count from cycles.log / CSV> | <anomalies, or "none"> |

## Gates — measured vs precommitted

One row per gate from the scenario's table in
`soak-acceptance-gates.md`. No gate may be omitted — a gate that could
not be measured is a FAIL with the reason stated.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| <gate> | <bound> | <value> | **PASS** / **FAIL** |

<N> / <M> gates pass. Analyzer verdict: `<pass|fail>`
(`verdict.json` / `report.json` archived below).

## Abort record

<Delete this section if the run was not aborted.>

| Field | Value |
|-------|-------|
| Trigger | <which abort criterion fired> |
| UTC time / elapsed | <when> |
| Evidence preserved | <run dir contents; daemon logs copied before destroy: yes/no> |
| Partial analyzer verdict | <verdict on the partial CSV> |

## Analysis notes

- <Sample-count accounting; RSS trajectory shape; any single-step
  anomalies and their disposition; daemon WARN/ERROR log census;
  host cohabitation events during the window.>

## Artifacts

Repo-archived (small, git-suitable):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/<run-id>/samples.csv` |
| run.json | `docs/artifacts/soak/<run-id>/run.json` |
| verdict/report JSON | `docs/artifacts/soak/<run-id>/<verdict>.json` |

Local-only (too large for git; preserved in the run directory):

| Artifact | Local path | Size |
|----------|------------|------|
| <daemon log etc.> | `tests/soak/runs/<run-id>/<file>` | <size> |

## Follow-ups

- [ ] <Actions arising from this run — for a FAIL, the tracked defect;
      for a PASS, any threshold or harness observations worth folding
      back into `soak-acceptance-gates.md`.>
