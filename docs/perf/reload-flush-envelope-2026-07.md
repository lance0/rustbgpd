# Reload-flush depool envelope — what drives it — 2026-07

The 1M actor-ceiling receipt (`actor-ceiling-1m-2026-07.md`) found that a
policy reload depools the node for ~2 s — not in the policy transition
(whose polls stay under the 200 ms readiness deadline) but in the
**post-commit outbound re-advertisement flush**. This receipt answers the
follow-on question that decides how to fix it (LAN-447):

> **Is the reload-flush `/readyz` stall driven by route volume
> (routes re-advertised) or by the peer fleet (how many peers)?**

The answer determines the fix: a route-volume-driven stall points at the
encoder; a peer-driven stall points at the per-peer distribution loop.

**Commit measured:** `ea29cbd0` (main). Real daemon, real BGP sessions,
release build, 64-core / 128 GiB box. Reloads driven by SIGHUP against a
**fully converged** daemon (readiness-gated: every point waits for
`bgp_rib_adj_out_prefixes` to reach the per-peer table size **and** three
consecutive fast-200 `/readyz` before reloading — see honesty notes on why
this gate is load-bearing). Stall = peak `/readyz` latency in the reload
window from a continuous ~150 ms scraper.

## Two controlled sweeps

**A — fixed fleet (100 clients, 100 changed), vary table → vary flush volume:**

| table | flush routes | `/readyz` stall (reload 1 / 2) |
|---|---|---|
| 100k | 9.9 M | 41 / 49 ms |
| 300k | 29.7 M | 22 / 39 ms |
| 500k | 49.5 M | 346 / 49 ms |

A **5× swing in re-advertised route volume moves the stall essentially not
at all** (tens of ms; the lone 346 ms was a non-reproduced first-reload
spike). Route volume is not the driver.

**B — fixed table (300 clients, 300k), vary changed peers → vary fleet work:**

| changed peers | flush routes | `/readyz` stall (reload 1 / 2) |
|---|---|---|
| 50 | 14.9 M | 103 / 114 ms |
| 150 | 44.9 M | 300 / 358 ms |
| 300 | 89.7 M | 610 / 457 ms (one 503) |

The stall grows **~linearly with changed-peer count** at a fixed fleet
(~1.7 ms per changed peer here), crossing the 200 ms deadline between 50 and
150 changed peers.

**Anchor (from the actor-ceiling receipt):** 500 clients, 1 M table, 300
changed → **1.6–2.4 s** (503 on every reload).

## Verdict

**The reload-flush depool is a peer-fleet phenomenon, not a route-volume
one.** Two independent signals:

1. **Volume is flat.** 9.9 M → 49.5 M routes at a fixed 100-peer fleet:
   ~30–50 ms throughout.
2. **Peers drive it, on two axes.**
   - *Changed peers*, at a fixed fleet: linear (50 → 110 ms, 150 → 330 ms,
     300 → 530 ms avg).
   - *Total fleet size*, superlinearly: 300 changed peers cost ~530 ms on a
     300-client fleet but ~2 s on a 500-client fleet (same 300 changed, same
     kind of change); and 50 changed on 300 clients (110 ms) already beats
     100 changed on 100 clients (30 ms). More registered peers ⇒ a bigger
     stall even with fewer of them changing.

Roughly, stall ≈ f(changed_peers × total_peers), superlinear at the top end,
**independent of table size**. The 200 ms readiness deadline is crossed at
~100–150 changed peers on a 300-client fleet and is left far behind (seconds)
at 500-client internet-scale fleets.

### What this means for LAN-447

The cooperative-flush fix should target the **per-peer distribution loop**,
not route encoding. The stall does not track how many routes are pushed; it
tracks how many peer Adj-RIB-Out streams the actor rebuilds/sequences before
yielding. A cooperative yield in the post-commit distribution keyed on
*peers processed* (not routes) would bound the stall at any fleet size. A
route-chunking fix would miss it entirely.

## Honesty notes

- **The readiness gate is load-bearing, and I got it wrong first.** An
  earlier run gated convergence on an `updates_sent` plateau and reloaded a
  daemon that was only ~40% converged and still flushing; `/readyz` was
  fail-fasting (0.2 ms 503 from the gate, never consulting the busy actor),
  so it measured nothing. Every number here is gated on real adj-out
  fullness **and** fast-200 readiness. Without that gate the measurement is
  silently meaningless.
- **Two reloads per point, real variance.** t500k reads 346/49 ms and pc300
  reads 610/457 ms — first-reload allocation effects and scheduling noise are
  visible. These are order-of-magnitude, direction-of-scaling results, not a
  fitted coefficient. The *direction* (peer-driven, volume-flat) is robust
  across every point.
- **Total-vs-changed peers are not fully orthogonalized.** Sweep B varies
  changed peers at a fixed 300-client fleet; the total-fleet axis is inferred
  from cross-sweep comparison (100 vs 300 vs 500 clients), not an independent
  single-variable sweep. The qualitative claim (both peer axes matter, volume
  does not) holds; a precise exponent would need a dedicated total-peer sweep.
- Single box, loopback sessions; `/readyz` sampled ~150 ms (the stall is the
  probe's own blocking latency, a direct measurement).

## Reproduce

```text
# one data point (readiness-gated SIGHUP reloads + continuous /readyz scraper):
python3 bench/scale/reloadstall/gen-scenario.py <clients> <dir> 1790 <changed>
target/release/rustbgpd <dir>/config.toml       # prometheus_addr = 127.0.0.1:9179
reloadstall <clients> <total_prefixes> 1790 <pid> \
    <dir>/member.rpol <dir>/gen-a.rpol <dir>/gen-b.rpol 0 600 <changed>
# wait until bgp_rib_adj_out_prefixes(peer) == per-peer table AND /readyz is a
# fast 200, then per reload: cp gen-{b,a}.rpol over member.rpol; kill -HUP <pid>;
# sample http://127.0.0.1:9179/readyz latency across the flush.
```
