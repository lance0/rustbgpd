# M37 Local-Origination MAC-Churn 24h Soak

**Status:** Template — fill this after the 24h run.
**Run ID:** `tests/soak/runs/m37-local-origination-YYYYMMDDTHHMMSSZ`
**Git SHA:** `TODO`
**Date:** `TODO`

## Verdict

TODO: `PASS` / `FAIL`.

One-sentence summary of whether local-MAC origination stayed stable under
bounded bridge-FDB churn.

## Run Shape

| Field | Value |
|-------|-------|
| Duration | TODO |
| Topology | `tests/interop/m37-evpn-local-origination.clab.yml` |
| Harness | `tests/soak/run-m37-local-origination-churn-soak.sh` |
| MAC pool | TODO |
| Live target | TODO |
| Churn cadence | TODO |
| Sample interval | TODO |
| Warmup excluded from RSS slope | TODO |

## Headline Results

| Signal | Result |
|--------|--------|
| BGP session | TODO |
| Local FDB count | TODO |
| FRR Type 2 count | TODO |
| `evpn_local_originations_total{action="inject"}` | TODO |
| `evpn_local_originations_total{action="withdraw"}` | TODO |
| `evpn_local_origination_errors_total` | TODO |
| `evpn_local_observations_dropped_total` | TODO |
| `evpn_duplicate_mac_moves_total` | TODO |
| PE RSS start / peak / end | TODO |
| Steady-state RSS slope | TODO |

## Pass / Fail Gates

| Gate | Expected | Result |
|------|----------|--------|
| BGP Established outside startup/shutdown | yes | TODO |
| `local_fdb_count` near `LIVE_TARGET_MACS` | yes | TODO |
| `frr_type2_count` near `LIVE_TARGET_MACS` | yes | TODO |
| Originations inject/withdraw advance with churn | yes | TODO |
| Origination errors stay flat | zero | TODO |
| Observation drops stay flat | zero | TODO |
| Duplicate-MAC moves stay flat | zero unless deliberately injected | TODO |
| RSS slope after warmup | flat / acceptable | TODO |

## Analysis Notes

TODO:

- How many samples were collected?
- Did the originator retained-state model plateau at the bounded MAC pool?
- Were any Type 2 routes stuck after final drain?
- Were there any daemon WARN/ERROR/FATAL log entries?
- Did FRR show any EVPN session resets?

## Artifacts

Raw artifacts stay local under `tests/soak/runs/` unless intentionally
published elsewhere.

| Artifact | Path |
|----------|------|
| samples.csv | `tests/soak/runs/m37-local-origination-.../samples.csv` |
| soak.log | `tests/soak/runs/m37-local-origination-.../soak.log` |
| churn.log | `tests/soak/runs/m37-local-origination-.../churn.log` |
| rustbgpd.log | `tests/soak/runs/m37-local-origination-.../rustbgpd.log` |
| consumer.log | `tests/soak/runs/m37-local-origination-.../consumer.log` |
| run.json | `tests/soak/runs/m37-local-origination-.../run.json` |

## Follow-Ups

TODO:

- Close or update <https://github.com/lance0/rustbgpd/issues/134>.
- Update `docs/evpn-alpha-soak.md` once the 24h run has a final verdict.
