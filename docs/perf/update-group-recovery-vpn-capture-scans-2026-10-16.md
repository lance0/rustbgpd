# Shared VPN recovery capture scans (16 October 2026)

> **Verdict: PASS** at `ed597e865e90ae8eceb0d26ead4bbcf50ae18e70`: every full-uc and
> full-vpn cell is at or below 1.10× flat. The first run at `0d84eb9860ea94739e084988770703c5fb0bf488`
> is retained as **FAIL**: shared VPN capture after key churn cost 3.66–4.68× flat.

## Shape

These are component capture scans on fresh GitHub-hosted Linux VMs. Each
profile and OLD order (sorted or shuffled) ran on a separate VM, using one
binary for both arms.

- **Profiles:** `full-uc` and `full-vpn` each hold 1,230,000 keys (1,000,000
  IPv4 and 230,000 IPv6). `evpn-soak` holds 37,500 keys.
- **Cells:** 2, 64 and 480 records, in a dense layout and an older-sparse
  layout.
  - *Dense:* the table is unchanged since the pool was built.
  - *Older-sparse:* the record count's worth of keys was removed and replaced
    after the pool was built.
- **Legs:** flat, candidate, candidate, flat (ABBA).
- **Per leg:** one shared cold anchor and one full capturing member. The flat
  arm is an explicit exact-flat capture.

This is the first scan in which the `full-vpn` candidate measures production's
shared VPN path (`vpn-pool-shared`) rather than an exact-flat control. The
[slot-indexed scan](update-group-recovery-slot-capture-scans-2026-10-15.md)
still records the earlier flat VPN policy, and the
[original capture-scan receipt](update-group-recovery-capture-scans-2026-10-15.md)
records the key-only path.

## Bar

The bar was declared before either run. Every `full-uc` and `full-vpn` cell,
in both OLD orders, must meet all three conditions:

- candidate/flat complete-capture wall ratio of at most **1.5**;
- zero refusals;
- every cell eligible.

`evpn-soak` and CPU-tick ratios are reported only.

## Results

| Run | Source | Profile | Sorted ratio range | Shuffled ratio range | Verdict |
| --- | --- | --- | ---: | ---: | --- |
| [38961458049](https://github.com/lance0/rustbgpd/actions/runs/38961458049) | `0d84eb98` | full-uc | 0.232–1.042 | 1.100–1.202 | — |
| 38961458049 | `0d84eb98` | full-vpn dense | 0.272–0.279 | 0.322–0.331 | — |
| 38961458049 | `0d84eb98` | full-vpn older-sparse | **3.660–3.822** | **4.458–4.679** | **FAIL** |
| [38968593819](https://github.com/lance0/rustbgpd/actions/runs/38968593819) | `ed597e86` | full-uc | 0.249–1.098 | 0.956–1.036 | PASS |
| 38968593819 | `ed597e86` | full-vpn dense | 0.247–0.261 | 0.267–0.275 | PASS |
| 38968593819 | `ed597e86` | full-vpn older-sparse | 0.243–0.275 | 0.255–0.271 | PASS |
| 38968593819 | `ed597e86` | evpn-soak (reported) | 0.878–2.162 | 1.305–1.832 | — |

In the passing run, flat `full-vpn` capture medians are 178–190 ms and shared
medians 44–50 ms. Neither run recorded a refusal.

**Why the first run failed.** After key churn, the older pool no longer matched
its table. Every VPN row was then probed through the pool's hash index, once in
the shape pass and again during population. That took 1,955,556–1,956,334
lookups per capture, and the random bucket and pool-key reads gave per-cell
medians of 741–804 ms.

**What fixed it.** Group tables now log their last 4,096 VPN key-set changes.
While the log covers a pool's version, capture skips row probes:

- it admits the pool's VPN range;
- it clears logged removals;
- it adds logged insertions as sparse keys.

Older-sparse captures now make 2, 132 and 1,258 lookups at 2, 64 and 480
replaced keys. A gap the log does not cover, or a partial projection, still
probes exactly.

## Scope

- **Component only.** One capturing member per leg; the remaining records are
  empty. These results are not daemon memory, fleet readiness, wire delivery or
  release qualification. Whole-system mass-dirty qualification and the
  release-candidate soak are separate receipts.
- **Small timing sample.** Two samples per arm per cell and 100 Hz CPU clocks
  do not describe a latency distribution. Cold anchor cost uses the same shared
  policy in both arms, so it supplies no sharing-on/off ratio.
- **Churn bound.** Changes beyond the 4,096-entry log, and partial projections,
  take the exact probe path, whose cost the first run shows.
- **EVPN.** EVPN group ownership remains disabled.

## Evidence

[`comparison.json`](artifacts/update-group-recovery-vpn-capture-scans-2026-10-16/comparison.json)
holds the curated per-cell ratios, medians, strategies, lookups and refusal
counts for both runs. Raw logs stay in each run's CI artifacts.

```json
{"run": 38968593819, "profile": "full-vpn/shuffled", "records": 480, "layout": "older-sparse",
 "strategy": "vpn-pool-shared", "capture_wall_ratio": 0.264, "candidate_comparisons": 1258}
```
