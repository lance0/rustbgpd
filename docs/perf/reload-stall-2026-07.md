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

**Commit measured:** `501ccc9d` (main; includes the slab route store
#821, global attribute interning #826, and the update-group resync
fixes #822/#823).

> **Receipt status: historical, invalidated pending rerun.** The original
> harness treated repeated base-prefix announcements as additional completion
> progress. A duplicate could therefore close an observer's measurement window
> before every unique prefix carrying the new policy-generation community had
> arrived. The figures below are retained as the original run record, but the
> `< 1 s` result is not release or acceptance evidence. The committed harness
> now requires every expected unique prefix with the expected generation marker;
> a corrected route-server-scale rerun will replace this notice.

## Historical headline (invalidated pending corrected rerun)

| Metric (700 route-server clients × 400,400 IPv4 routes, churn running) | Value |
|---|---|
| **UPDATE stall** (worst per-observer delivery gap spanning a reload, median of 4 reloads, p50 across 700 observers) | **0.77 s** |
| UPDATE stall, worst single observer in any reload | **0.85 s** |
| Expected inter-UPDATE gap from churn alone (control window, p50 / max) | 19 ms / 42 ms |
| Session flaps / holds missed across all reloads | 0 (700/700 Established throughout) |
| Full new-policy re-advertisement, per-observer completion (median reload, p50 / max) | 155 s / 313 s |
| Reload wall time (SIGHUP → `config reload complete`, median of 4) | **310.6 s** (~0.45 s/peer) |
| Concurrent `rbgp health` query latency (baseline → during reload, p50) | 7.8 ms → **207.8 ms** (max 235 ms) |
| Daemon RSS (converged → after 4 reload cycles) | 814 MiB → 1316 MiB (plateaus; +60/+10 MiB on cycles 3/4) |

**Historical verdict, not currently accepted: the < 1 s stall gate appeared to
hold — but marginally (0.85 s worst
case), and full repropagation of the new policy is minutes, not
seconds, with the responsible code path identified below.** UPDATEs
never stop flowing: churn keeps being delivered throughout the entire
~5-minute reload with no gap ever reaching one second, no session
flap, and the daemon answering queries (two orders of magnitude
slower than idle) the whole time.

## Environment

| Field | Value |
|---|---|
| Hardware | AMD Ryzen Threadripper 7970X (32 cores / 64 threads), 125 GiB RAM |
| Kernel | Linux 6.17.0-35-generic |
| rustc | 1.97.0 (2026-07-07) |
| Build | `--release`, stock daemon config (8 tokio workers — the capped default) |
| Load discipline | runs load-gated at 1-min loadavg < 2.0; the harness is the only load during a run |

## Scenario

An AMS-IX-like shape, scaled to one host:

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
    output-neutral against the announced table, so the wire volume
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
0.6 s, full 280M-NLRI initial fanout (400,400 routes × 699 receivers)
decoded by all observers 2.8 s later, RSS 811 MiB.

## Numbers

**UPDATE stall** = the largest gap between consecutive UPDATE
arrivals at an observer in its window [SIGHUP, own full-table
completion], including the leading SIGHUP→first-UPDATE gap.
Distribution is across the 700 observers.

| Reload | stall p50 | stall p95 | stall max | completion p50 | completion max | reload wall (log) | RSS after |
|---|---|---|---|---|---|---|---|
| 1 (A→B) | 809 ms | 809 ms | 845 ms | 161.4 s | 318.6 s | 318.6 s | 1120 MiB |
| 2 (B→A) | 773 ms | 774 ms | 802 ms | 154.9 s | 313.2 s | 313.2 s | 1246 MiB |
| 3 (A→B) | 747 ms | 747 ms | 776 ms | 154.5 s | 308.0 s | 308.0 s | 1306 MiB |
| 4 (B→A) | 760 ms | 762 ms | 786 ms | 154.7 s | 307.9 s | 307.9 s | 1316 MiB |

- Net of the 19 ms expected churn gap, the stall is ~0.73–0.83 s in
  every reload. The tight p50≈p95 spread says the worst gap is one
  global manager-occupancy event seen by all observers, not
  per-observer noise.
- Per-observer completion p50 ≈ 155 s ≈ half the wall: members are
  re-advertised one at a time at a steady ~0.45 s/peer (the 700
  `soft reset in requested` log lines are spaced 442–477 ms apart),
  so a given member's new-policy view lands anywhere from seconds to
  ~5 minutes after SIGHUP, uniformly.
- Aggregate re-advertisement throughput during a reload: 279.9 M NLRI
  / ~310 s ≈ 0.9 M NLRI/s — ~50× below the 45–55 M NLRI/s the same
  pipeline sustains on the cold-convergence flood, which is what
  makes the per-peer path below the indictment.
- Concurrent queries: p50 7.8 ms baseline → 207.8 ms during every
  reload window (p95 208.8 ms, max 235 ms, n=4928). Priority queries
  are serviced only between manager messages, and during a reload
  nearly every message is a long per-member resync.
- RSS grows +306 MiB on the first swap cycle and plateaus by cycle 4
  (+10 MiB) — consistent with the global intern table (#826) carrying
  both attribute generations plus per-member resync transients, not a
  leak signature. (An exploratory identical run showed the same
  plateau shape.)

## Where the ~0.45 s/peer goes (the indicted path)

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
   message (the 208 ms probe number is this queue wait; the ~0.8 s
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
- The stall metric counts *any* UPDATE delivery (churn, resync
  announces, withdraws). Completion counts only base-table
  announcements (churn prefixes live in a disjoint range and are
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
  per-peer fallback and would see strictly worse reload behavior
  (bounded by the mixed-fleet scenario in
  [`scale-receipt-2026-07.md`](scale-receipt-2026-07.md)).
- `rbgp health` latency includes process spawn + gRPC connect
  (~7.8 ms of it, per the baseline); the reload delta is manager
  queue wait.
- Stall percentiles for reload windows have no trailing-gap term (the
  window ends at the observer's completion event); control-window
  gaps include the trailing gap to window end.
- Single host, one shape. The per-peer pacing scaled linearly in an
  exploratory run at the same shape (like-for-like numbers within
  5%); other table×peer sizes were not swept.

## Reproduction

The harness is committed at `bench/scale/reloadstall/` (a standalone
crate kept out of the workspace; build it explicitly). Structure: a
single tokio binary that (1) dials 700 real BGP sessions into a
release-build
rustbgpd started from a generated config (700 route-server-client
neighbors, global rpol chains, gRPC UDS on), binding stub sources
127.1.x.y with router-ids 240.1.x.y — higher than the daemon's, so
the inbound connection wins RFC 6286 collision resolution against the
daemon's active dial to the unreachable stub port 179; (2) announces
per-member slices (900-NLRI packed UPDATEs, ORIGIN IGP + own-ASN
AS_PATH + non-loopback NEXT_HOP — a 127/8 NEXT_HOP is rejected with
UPDATE error subcode 8); (3) answers ROUTE_REFRESH by re-announcing
its slice; (4) flaps churn blocks from 8 members; (5) copies the
next-generation `.rpol` over the live file, SIGHUPs the daemon, and
waits until every observer has received every unique base-table prefix
except its own carrying the expected policy-generation community; (6)
reports per-observer max-gap / completion percentiles, records delivered
communities to verify the live policy generation, and reads daemon RSS from
`/proc`. Reload
wall times come from the daemon's JSON log (`config reload
complete`); the probe is a 50 ms shell loop timing `rbgp health`
against the UDS socket.

Build and run shape:

```text
cd bench/scale/reloadstall && cargo build --release
./target/release/reloadstall 700 400400 <port> <daemon_pid> \
    <live.rpol> <gen-a.rpol> <gen-b.rpol> 4 30
```

after a load-gated daemon start; the two policy generations are
exactly the chains quoted in the Scenario section.
