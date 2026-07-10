# M33 50k-route EVPN scale soak — postmortem (attribute-intern leak, scale axis)

One-page record of a ~10-hour M33 EVPN scale soak confirming the
Adj-RIB-In attribute-intern table stays bounded under **50 000 Type 2
EVPN routes plus sustained churn** on v0.45.0 HEAD. This is the
*scale* axis of the EVPN memory-leak evidence: the
[#590](https://github.com/lance0/rustbgpd/pull/590) /
[#592](https://github.com/lance0/rustbgpd/pull/592) fix and the
surrounding v0.45.0 allocation/correctness audit were previously
receipted only under MAC-mobility churn (M67, 2026-06-28) — never at
50k-route depth. This soak fills that gap.

The run was deliberately stopped at ~10h once the flat-RSS signal was
unambiguous: a leak of the pre-fix magnitude (~279 MB/h) would be
**+2.8 GB** by 10h; measured growth was **+0.01 MB**. It is a
leak-confirmation receipt, not a production-default-flip gate (no
default was being flipped).

## What this soak exercised

The harness (`tests/soak/run-m33-soak.sh`) drives the
`tests/interop/m33-evpn-scale.clab.yml` topology: a rustbgpd
route-reflector target fed by two tester peers advertising 25 000
Type 2 EVPN routes each (50 000 total) at 5 000 routes/s, then
sustaining churn at 1 000 routes/s for the run. A synthetic monitor
peer verifies Loc-RIB convergence. Every advertised route carries a
distinct attribute set, so a leak in the EVPN attribute-intern table
would grow RSS in lock-step with churn — the same failure mode the
fix addresses, exercised here at route scale rather than via MAC
mobility.

## Run metadata

| Field | Value |
|---|---|
| Started | `2026-07-01T01:40:45Z` |
| Runtime | ~10.1 h (600 samples @ 60 s), stopped on conclusive-flat signal |
| Build `git_rev` | `c273118e` (clean tree, v0.45.0 HEAD) |
| Image | `sha256:dbb19308…` |
| Topology | `tests/interop/m33-evpn-scale.clab.yml` |
| Route depth | 50 000 Type 2 (25 000 × 2 testers) |
| Advertise / churn rate | 5 000 / 1 000 routes per second |
| Sample interval | 60 s |
| Warmup discard | 600 s |

## Results

### RSS — dead flat (the headline)

| metric | value |
|---|---|
| first (post-warmup) | 82.87 MB |
| last | 82.88 MB |
| peak | 84.14 MB |
| steady-state slope | **0.033 MB/h** |

- Least-squares slope over 590 post-warmup samples: **0.033 MB/h** —
  ~30× under the analyzer's 1.0 MB/h fail cap, and ~8 400× below the
  **+279 MB/h** dead-linear growth the leak produced before the fix.
- RSS held at ~83 MB across the entire run at 50k-route depth; the
  0.01 MB net change over 10h is noise. Textbook flat plateau, not a
  leak.

### Control-plane health — all clean

- Loc-RIB converged to **50 000** in 12 s; held 50 000 (adj-out
  100 000) through terminal.
- `session_flaps_total` = 0; `outbound_drops_total` = 0; gRPC health
  failures = 0; no daemon restart.
- 3.48 M messages sent / 1.74 M received across the run.

### Analyzer verdict

`analyze-soak.py` → **`verdict: clean`**, `failures: []`. 590 steady
samples, slope 0.033 MB/h, peak 84 MB (cap 512 MB).

## Conclusion

**PASS.** The attribute-intern table stays bounded under 50 000-route
EVPN scale plus churn on v0.45.0 HEAD. Combined with the M67
MAC-mobility receipt (2026-06-28), the leak fix is now confirmed on
both the mobility-churn and route-scale axes.

## Raw data

Tracked here so the postmortem stays self-contained when the soak
host is recycled (`tests/soak/runs/` stays off-repo):

- [`artifacts/soak/m33-evpn-scale-20260701T014045Z/samples.csv`](../artifacts/soak/m33-evpn-scale-20260701T014045Z/samples.csv)
- [`artifacts/soak/m33-evpn-scale-20260701T014045Z/soak.log`](../artifacts/soak/m33-evpn-scale-20260701T014045Z/soak.log)
- [`artifacts/soak/m33-evpn-scale-20260701T014045Z/report.json`](../artifacts/soak/m33-evpn-scale-20260701T014045Z/report.json)
- [`artifacts/soak/m33-evpn-scale-20260701T014045Z/run.json`](../artifacts/soak/m33-evpn-scale-20260701T014045Z/run.json)

## Cross-references

- [`docs/soaks/soak-m67-link-drain-24h-evpn-leak.md`](soak-m67-link-drain-24h-evpn-leak.md) —
  the MAC-mobility axis of the same fix.
- [`docs/soaks/soak-gate8b-mac-churn-10h-leak.md`](soak-gate8b-mac-churn-10h-leak.md) —
  companion MAC-mobility-churn soak run the same night.
- `tests/soak/run-m33-soak.sh` / `tests/soak/analyze-soak.py` —
  harness + gate analyzer.
