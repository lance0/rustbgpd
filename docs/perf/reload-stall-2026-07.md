# Reload UPDATE-stall at route-server scale — 2026-07

How long do UPDATEs stall while a route server reloads a changed
policy? This is the route-server operator KPI: the incumbents'
best-known reconfiguration stories are minutes-scale (BIRD's reconfig
cost grows with config size and motivated BIRD 3's `reload filters
in/out`; OpenBGPD's most-quoted operator receipt is an IXP reload
going from tens of minutes to "under 30 seconds, hitless"). Nobody
publishes sub-second stall numbers, so this receipt measures one, at
the receiver, under churn, against a pre-committed gate:

> **Gate: UPDATE-delivery stall < 1 s during a full import+export
> policy swap at 700 clients × 400k routes, with live churn.**

**Commit measured:** `61efe075`
(`fix/outbound-oversized-group-truncation`; main `25979227` plus the
outbound size-chunking fix described in
[Why this supersedes the earlier run](#why-this-supersedes-the-earlier-run),
and — from earlier — the slab route store #821, global attribute
interning #826, and the update-group resync fixes #822/#823).

## Headline

| Metric (700 route-server clients × 400,400 IPv4 routes, churn running) | Value |
|---|---|
| **UPDATE stall** (worst per-observer delivery gap spanning a reload, median of 4 reloads, p50 across 700 observers) | **0.76 s** |
| UPDATE stall, worst single observer in any reload | **0.82 s** |
| Expected inter-UPDATE gap from churn alone (control window, p50 / max) | 19 ms / 42 ms |
| Session flaps / holds missed across all reloads | 0 (each peer reached Established once; daemon logged 0 NOTIFICATIONs and 0 hold-timer expiries) |
| Full new-policy re-advertisement, per-observer completion (median reload, p50 / max) | 155 s / 309 s |
| Reload wall time (SIGHUP → `config reload complete`, median of 4) | **308 s** (~0.44 s/peer) |
| Concurrent `rbgp health` query latency (baseline → during reload, p50) | 6 ms → **207 ms** (max 232 ms) |
| Daemon RSS (converged → after 4 reload cycles) | 815 MiB → 1303 MiB (grows; not a clean plateau — see honesty notes) |

**Verdict: the < 1 s stall gate holds — but marginally (0.82 s worst
case), and full repropagation of the new policy is minutes, not seconds,
with the responsible code path identified below.** UPDATEs never stop
flowing: churn keeps being delivered throughout the entire ~5-minute
reload with no gap ever reaching one second, no session flap, and the
daemon answering queries (two orders of magnitude slower than idle) the
whole time. Every one of the 700 clients verifiably received all 399,828
non-self base prefixes carrying the new policy-generation community —
which is what makes this run acceptance evidence where the July
over-count was not.

## Status at later heads

These numbers are pinned to `61efe075` and do not hold at later
commits. A 2026-07-16 rerun of the identical campaign at `02f1f2a7`
was rejected: observer stall p50 rose to ~1.03 s (above the gate) with
a flat per-observer distribution consistent with the paced
commit/resync sweep introduced by the cooperative policy-transition
flush, and per-observer completion rose from ~155 s to ~273 s p50
(LAN-458); post-campaign TERM shutdown also wedged in a dirty-resync
loop against closed peer channels until SIGKILL (LAN-459). The rerun's
readiness plane was strictly better than this receipt's (health
queries bounded at ~225 ms worst by the response-deadline fix, vs
232 ms here, and degraded only inside re-advertisement windows). This
receipt remains valid for its commit; a replacement receipt lands only
after LAN-458/LAN-459 close and a rerun passes acceptance (tracked in
LAN-350).

## Why this supersedes the earlier run

An earlier July run at this shape reported effectively the same figures
(0.77 s stall / 155 s completion) but was withdrawn as not-acceptance
evidence, for two independent reasons — both now resolved:

1. **Completion over-counting (harness).** The original harness treated
   repeated base-prefix announcements as additional completion progress,
   so a duplicate could close an observer's measurement window before
   every unique prefix carrying the new policy-generation community had
   arrived. The harness now requires every expected *unique* base prefix
   with the expected generation marker (a per-observer bitmap, own slice
   excluded), so completion means the observer genuinely holds the full
   re-advertised table under the new policy — not an early duplicate.

2. **Silent outbound truncation (daemon).** Validating the corrected
   harness at a smaller shape (20 clients × 20,000 routes, so 1000
   same-attribute /24s per source ≈ 4114 bytes) exposed a real transport
   bug: an Adj-RIB-Out attribute group larger than one BGP message was
   built as a single UPDATE, rejected by the encoder (`MessageTooLong`),
   logged, and the rest of the batch abandoned — but the RIB's channel
   send had already committed the whole logical batch, so the partial
   delivery was never reported back and the peer was left silently
   under-advertised at whole-group boundaries, with no dirty-resync
   recovery. Fixed by chunking all four IPv4-unicast paths to the
   negotiated message size (commit `61efe075`, with regression tests).
   **This specific 700 × 400,400 shape does not trigger that bug** — its
   per-source groups are only 572 prefixes (≈2.3 KB, under 4096) — so the
   numbers here are unchanged by the fix; but the fix is a prerequisite
   for trusting the harness at shapes with larger same-attribute groups
   (fewer clients × larger tables, or a full-table peer).

The upshot: the numbers land where the withdrawn run did, but are now
backed by a completion criterion that cannot false-positive and a daemon
that cannot silently drop part of the re-advertisement.

## Environment

| Field | Value |
|---|---|
| Hardware | AMD Ryzen Threadripper 7970X (32 cores / 64 threads), 125 GiB RAM |
| Kernel | Linux 6.17.0-35-generic |
| Build | `--release`, stock daemon config (8 tokio workers — the capped default) |
| Load discipline | 1-min loadavg 0.58 at start; the harness is the only load during a run |

## Scenario

An AMS-IX-like shape, scaled to one host, generated by
`bench/scale/reloadstall/gen-scenario.py`:

- **rustbgpd as a transparent route server**: 700 `[[neighbors]]`
  blocks, each eBGP with a distinct ASN (64512–65211),
  `route_server_client = true`, IPv4 unicast only, `hold_time = 180`.
  Global rpol chains: `import_chain = ["member-in"]`,
  `export_chain = ["member-out"]`.
- **700 real BGP stub clients** over loopback TCP (real OPEN/
  KEEPALIVE/UPDATE wire exchange, distinct 127.1.x.y source
  addresses). Each announces its own 572-prefix slice of a 400,400 ×
  /24 table and decodes every received UPDATE, timestamping arrivals.
  Every client is an observer.
- **Live churn throughout**: 8 members each flap a dedicated
  16-prefix block every 125 ms (staggered), ≈ 64 UPDATE events/s
  aggregate delivered to every observer. The measured no-reload
  baseline (control window) puts the expected worst inter-UPDATE gap
  at 19 ms (p50) / 42 ms (max) per observer.
- **The reload**: overwrite the live `.rpol` file and SIGHUP. Both
  chains are content-different from the installed generation, so the
  content-identical skip path (#775) cannot trigger for any peer:
  - `member-out`: `add community 65500:1000` ⇄ `65500:2000` — every
    delivered route's attributes change, forcing a full
    re-advertisement to every member;
  - `member-in`: a `route.prefix == 192.0.2.0/24 { reject }` term
    ⇄ `198.51.100.0/24` — content-real (each peer's import chain is
    reinstalled and Route Refresh fires: all 700 stubs re-announce
    and 400k routes re-enter through the new chain), but
    output-neutral against the announced table (both reject prefixes
    are outside the 20.0.0.0–26.x base table), so the wire volume
    stays attributable to exactly one export-driven re-advertisement.
- 4 consecutive reloads (A→B→A→B) on a hot, converged daemon, 20 s
  quiesce between; the policy generation actually delivered is
  verified per reload by sampling communities off decoded UPDATEs
  (65500:2000 after odd reloads, 65500:1000 after even ones — both
  observed as expected).
- A concurrent-query probe (`rbgp health`, which round-trips the RIB
  manager's priority query channel) runs in a 50 ms loop for the
  whole run.

Cold convergence for scale context: all 700 sessions Established in
0.6 s, full 279.9M-NLRI initial fanout (399,828 routes × 700 receivers)
decoded by all observers 2.8 s later, RSS 815 MiB.

## Numbers

**UPDATE stall** = the largest gap between consecutive UPDATE
arrivals at an observer in its window [SIGHUP, own full-table
completion], including the leading SIGHUP→first-UPDATE gap.
Distribution is across the 700 observers.

| Reload | stall p50 | stall p95 | stall max | completion p50 | completion max | reload wall (log) | RSS after |
|---|---|---|---|---|---|---|---|
| 1 (A→B) | 790.6 ms | 791.2 ms | 820.5 ms | 164.3 s | 323.1 s | 323.1 s | 1107 MiB |
| 2 (B→A) | 763.3 ms | 763.5 ms | 790.0 ms | 155.0 s | 309.3 s | 309.3 s | 1181 MiB |
| 3 (A→B) | 755.8 ms | 757.8 ms | 785.2 ms | 154.8 s | 308.0 s | 308.0 s | 1209 MiB |
| 4 (B→A) | 743.8 ms | 745.8 ms | 770.6 ms | 154.0 s | 304.6 s | 304.6 s | 1303 MiB |

- Net of the 19 ms expected churn gap, the stall is ~0.72–0.77 s in
  every reload. The tight p50≈p95 spread says the worst gap is one
  global manager-occupancy event seen by all observers, not
  per-observer noise. The stall trends slightly *down* across the four
  cycles (0.79 → 0.74 s) as the hot daemon warms further.
- Per-observer completion p50 ≈ 155 s ≈ half the wall: members are
  re-advertised one at a time at a steady ~0.44 s/peer, so a given
  member's new-policy view lands anywhere from seconds to ~5 minutes
  after SIGHUP, uniformly. Reload wall (SIGHUP → `config reload
  complete`) equals the slowest observer's completion, confirming the
  reload handler drives the per-member resync synchronously.
- Aggregate re-advertisement throughput during a reload: 279.9 M NLRI
  / ~308 s ≈ 0.9 M NLRI/s — ~50× below the 45–55 M NLRI/s the same
  pipeline sustains on the cold-convergence flood, which is what
  makes the per-peer path below the indictment.
- Concurrent queries: 6 ms baseline (min sample) → p50 207 ms during
  the reload windows (p95 208 ms, p99 209 ms, max 232 ms, n=6729).
  Priority queries are serviced only between manager messages, and
  during a reload nearly every message is a long per-member resync.

## Where the ~0.44 s/peer goes (the indicted path)

No fix is coded here; the receipt pins the mechanism:

1. **The per-peer fan-out is strictly sequential.**
   `apply_resolved_policy_snapshot`
   (`src/peer_manager/policy.rs`) walks all 700 peers one at a time;
   for each it awaits the session-side chain hot-apply, then the RIB
   `ReplacePeerExportPolicy` round-trip, then fires Route Refresh.
2. **Each RIB round-trip is one long manager message.**
   `handle_replace_peer_export_policy`
   (`crates/rib/src/manager/distribution/mod.rs`) runs the update-group
   recompute *and* the member's full resync — baseline diff plus
   emission of all ~400k changed routes — synchronously before
   replying. Churn distribution and priority queries wait out each
   message (the 207 ms probe number is this queue wait; the ~0.8 s
   worst delivery gap is its back-to-back worst case).
3. **The regroup work is per-member, not per-group.**
   `recompute_update_group` (`crates/rib/src/manager/update_groups.rs`)
   snapshots the member's full advertised view
   (`member_view_snapshot`, ~400k entries) as its resync baseline,
   then diffs it against the destination group table. All 700 members
   migrate between the *same two* content-keyed groups, so
   essentially the same 400k-route diff is recomputed 700 times. The
   shared-staging economics that make cold convergence 50× faster
   (ADR-0098: one staged table, one eval, per-member emission of an
   Arc-shared payload) do not exist on the regroup seam.

The corresponding levers (a shared group-to-group migration diff
computed once per edge; chunking the per-member resync so queries and
churn interleave mid-member) are design work for a follow-up issue,
deliberately not part of this receipt.

## Honesty notes

- Loopback TCP on one host: no NIC, no RTT, no loss. Syscall and PDU
  counts match production; receiver timestamps are taken in the stub
  after full wire framing+decode of each UPDATE.
- **Completion counts unique prefixes with the new marker, once each.**
  Each observer completes only when it has received every base prefix
  except its own slice carrying the reload's expected community; a
  duplicate re-advertisement does not advance it, and its own slice is
  excluded. This is the correction over the withdrawn July run.
- The stall metric counts *any* UPDATE delivery (churn, resync
  announces, withdraws). Completion counts only base-table
  announcements (churn prefixes live in a disjoint 172.x range and are
  excluded by prefix).
- The churn rate (64 events/s aggregate) is modest by design — high
  enough to timestamp delivery continuously, low enough that the
  expected gap (19 ms) is negligible against the ~0.8 s signal being
  measured.
- The import-chain change is deliberately output-neutral (term
  content changes; no route's verdict changes). The costly parts
  still happen — per-peer reinstall, 700 Route Refreshes, 400k-route
  re-ingest through the new chain — but the export swap alone drives
  the re-advertisement, keeping the wire volume interpretable. A
  verdict-changing import swap would add best-path churn on top.
- All 700 members share global chains and one update group. Fleets
  with per-peer-context chains (update-group disqualifiers) ride the
  per-peer fallback and would see strictly worse reload behavior.
- **Session continuity is cross-checked daemon-side, not just at the
  stub.** The harness's own "session up" flag is a TCP-reader signal, not
  a BGP FSM state, so the flap claim is taken from the daemon log: each of
  the 700 peers logged exactly one transition to Established (no
  re-establishment), with zero NOTIFICATIONs and zero hold-timer
  expiries. The frequent `connect`/`active` transitions in the log are the
  daemon's own active-open retries to the unreachable stub port 179
  (RFC 6286 collision resolution keeps the inbound session), not the
  established sessions flapping.
- **RSS did not cleanly plateau.** It grew 815 → 1107 → 1181 → 1209 →
  1303 MiB across the four cycles (+292 / +74 / +28 / **+94**). Cycle 4
  grew more than cycle 3, so this is not a settled plateau; consistent
  with the global intern table carrying both attribute generations plus
  per-member resync transients, but a longer run (or a dhat pass across
  ≥8 cycles) is needed to distinguish transient retention from slow
  growth. The daemon `outbound channel full — marking dirty for resync`
  path fired 761 times during the run (slow-stub backpressure on the
  resync flood); every observer still reached full completion, so the
  dirty-resync recovered — distinct from the now-fixed truncation, which
  it could not.
- Stall percentiles for reload windows have no trailing-gap term (the
  window ends at the observer's completion event); control-window
  gaps include the trailing gap to window end.
- Single host, one shape; other table×peer sizes were not swept.

## Reproduction

The harness is committed at `bench/scale/reloadstall/` (a standalone
crate kept out of the workspace; build it explicitly). The daemon-side
scenario — the 700-neighbor config and the two `.rpol` generations — is
generated by `bench/scale/reloadstall/gen-scenario.py`, whose addressing
matches the harness (`stub_addr`/`stub_asn`/`base_prefix` in
`src/main.rs`) exactly.

The harness (1) dials 700 real BGP sessions into a release-build
rustbgpd started from the generated config, binding stub sources
127.1.x.y with router-ids 240.1.x.y — higher than the daemon's, so the
inbound connection wins RFC 6286 collision resolution against the
daemon's active dial to the unreachable stub port 179; (2) announces
per-member slices (900-NLRI packed UPDATEs, ORIGIN IGP + own-ASN
AS_PATH + non-loopback NEXT_HOP — a 127/8 NEXT_HOP is rejected with
UPDATE error subcode 8); (3) answers ROUTE_REFRESH by re-announcing its
slice (one outstanding reply per peer); (4) flaps churn blocks from 8
members; (5) copies the next-generation `.rpol` over the live file,
SIGHUPs the daemon, and waits until every observer has received every
unique base-table prefix except its own carrying the expected
policy-generation community; (6) reports per-observer max-gap /
completion percentiles, records delivered communities to verify the live
generation, reads daemon RSS from `/proc`, and fails the run non-zero on
any daemon UPDATE that does not decode. Reload wall times come from the
daemon's JSON log (`config reload complete`); the probe is a 50 ms shell
loop timing `rbgp health` against the UDS socket.

Build and run shape:

```text
# short run dir: the gRPC UDS path must fit SUN_LEN (~108 bytes)
python3 bench/scale/reloadstall/gen-scenario.py 700 /tmp/rls/full 1800
cd bench/scale/reloadstall && cargo build --release
# start the release daemon on the generated config, then:
./target/release/reloadstall 700 400400 1800 <daemon_pid> \
    /tmp/rls/full/member.rpol /tmp/rls/full/gen-a.rpol \
    /tmp/rls/full/gen-b.rpol 4 30
```

after a load-gated daemon start.
