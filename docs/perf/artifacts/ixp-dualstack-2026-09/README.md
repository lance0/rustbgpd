# Dual-stack route-server reload receipt — raw artifacts (2026-09)

Raw data behind [`../../ixp-dualstack-2026-09.md`](../../ixp-dualstack-2026-09.md):
the dual-stack (IPv4 unicast + IPv6 unicast on every member session)
policy-reload campaign through the shared `bench/scale/reloadstall`
harness, rustbgpd only.

## Pinned shape (fixed before the first measured cell)

This section was committed before any cell below was run. A cell that
does not match it is published as a deviation, not silently rerun.

**Members.** `N` eBGP route-server-client sessions over IPv4 loopback
transport (`127.1.x.y` to `127.0.0.1:1790`, router-id `240.1.x.y`,
ASN `64512 + i`, hold time 180). Every session negotiates **both**
`ipv4_unicast` and `ipv6_unicast` (RFC 4760 multiprotocol capabilities
in both OPENs); a session whose peer OPEN omits either family fails
establishment and the cell fails. There are no IPv6-transport sessions:
"dual-stack" here means two negotiated families per session, which is
the common IXP member shape.

**Routes: total, not per family.** Each member announces **286 IPv4
/24s plus 286 IPv6 /48s**, so:

| Rung | Members | IPv4 routes | IPv6 routes | Total unique routes |
|---|---|---|---|---|
| 1 (correctness) | 20 | 5,720 | 5,720 | 11,440 |
| 2 | 200 | 57,200 | 57,200 | 114,400 |
| 3 (full) | 700 | 200,200 | 200,200 | **400,400 total** |

The full shape is **400,400 total, 200,200 per family**. It is not
400,400 routes per family, and it is not comparable with the IPv4-only
700 × 400,400 matrix in [`../../ixp-matrix-2026-07.md`](../../ixp-matrix-2026-07.md),
which carries 400,400 IPv4 routes and no IPv6.

**Distribution and overlap.** Disjoint contiguous per-member slices in
each family: member `i` owns global indexes `[286 i, 286 (i + 1))` of
both families. IPv4 index `k` is `20.0.0.0/24 + k` (one first octet
per 65,536 prefixes, `base_prefix`); IPv6 index `k` is
`3001:HHHH:LLLL::/48` with `HHHH = k >> 16`, `LLLL = k & 0xffff`
(`base_prefix6`). Every prefix has exactly one announcer; the
received-view overlap dimension of the IRR receipts is out of scope.
Next hops are synthetic and never resolved: `10.9.x.y` (IPv4 body
NEXT_HOP) and `fd09::x:y` (IPv6 `MP_REACH_NLRI`); route-server mode
passes them through.

**Cohorts.** The first `changed` members use the `member-out` export
chain that changes between generations; the remaining `stable` members
use the content-stable `stable-out` chain (community `65400:9000`).
The import chain `member-in` is byte-identical across generations in
every cell here.

| Rung | changed | stable |
|---|---|---|
| 20 | 16 | 4 |
| 200 | 170 | 30 |
| 700 | 600 | 100 |

**Policy shapes.** Two cells per rung, each a fresh daemon start:

- **P — permit-set-preserving.** Generation A tags every exported route
  with `65400:1000`; generation B with `65400:2000`. Nothing is
  filtered; every changed observer must receive every non-own prefix
  of **each** family carrying the new marker.
- **F — filtering.** As P, plus generation B rejects the named
  prefix-set `filtered` = base indexes `0..64` of **each** family (64
  IPv4 + 64 IPv6 = 128 named prefixes, all announced by member 0)
  before tagging; generation A permits them again. The **named churn**
  is therefore 128 prefixes that must be withdrawn at every changed
  observer other than member 0 on a B reload and re-announced with the
  A marker on the next A reload. **Bystanders** are every other
  prefix (must carry the new marker, never be withdrawn), every stable
  observer (must see fresh `stable-out` markers in both families after
  the changed cohort completes, and never a base withdrawal), and the
  unfiltered family half of each member's table.

**Churn schedule.** From convergence to the end of the cell, the last
8 members each alternately announce and withdraw a 16-prefix IPv4
block (`172.(16 + c).j.0/24`) **and** a 16-prefix IPv6 block
(`3002:c:j::/48`) every 125 ms, staggered across churners: about 64
UPDATE events per second per family, aggregate. Churn prefixes sit
outside both base spaces and never advance a completion bitmap.

**Reload schedule per cell.** Establish (waves of 64), converge (exact
per-family unique-prefix bitmaps at every observer: full table minus
own slice, in each family), 3 s churn settle, 30 s control window,
then **4 SIGHUP reloads: B, A, B, A**, each: copy the generation file
over the live `.rpol`, take the trigger timestamp, SIGHUP, wait until
every changed observer completes **both** families (and, in F, has
received every named withdrawal), then wait until every stable
observer has a fresh stable marker in **both** families, record the
row, 20 s quiesce.

**Acceptance per cell.** All sessions up throughout; zero daemon
UPDATE decode errors; every changed observer completes each family on
its own bitmap; stable markers fresh in both families at every stable
observer after each reload; `filtered_leaked = 0`,
`bystander_withdrawn = 0`, `stable_withdrawn = 0`; named withdrawals
equal to the expected count in each family. Any miss fails the cell
and is published as a failure.

**Instruments.** Per family and per reload, over the changed
observers: completion (trigger to last expected prefix), leading stall
(trigger to first marker prefix), and worst inter-UPDATE gap
restricted to that family's UPDATEs; plus the historical any-family
row. Daemon `VmRSS` before and after each reload (harness), process
RSS at 5 s cadence (`rss-sampler.sh`), and `VmHWM` at teardown.
Operator queries: a 50 ms `rbgp health` loop and a 250 ms
`rbgp rib --prefix` loop over `20.0.0.0/24` and `3001::/48` against the
cell's gRPC socket, latency and exit code per call.

**Host discipline.** One cell at a time behind the shared host lock,
the quiet-host gate (1-minute load < 2.0, every governor
`performance`, no compiler or daemon competitors, no swap movement
between two samples), a 100 GiB process-tree RSS abort, and a 300 s
cool-down after every cell. The 20-member rung is a correctness rung:
it may run on a busy host and its timings are not quoted. Rung 3
(700) is the receipt rung: it runs only through
`bench/scale/matrix/run-matrix.sh` under the full gate, as two fresh
runs of each policy shape in one quiet window on a pinned
implementation. Rung 2 (200) is a scale-validation rung ahead of the
receipt rung: it runs behind the host lock with no compiler or daemon
competitors, but the session that ran it could not set the CPU
governor (the host was on `powersave` throughout), so its timings are
published as indicative shape validation, not as receipt-grade
numbers; the gated driver command for a receipt-grade rerun is in the
receipt.

**Out of scope.** Comparison with BIRD or OpenBGPD (the cross-daemon
generators are IPv4-only; a comparison needs the identical dual-stack
input), any IPv6 optimization claim, overlap, flapstorm, and the
max-prefix trip cycle.

## Layout

One directory per cell, named `rung<N>-<members>-<P|F>[-<run>]`, plus
`negative-20-v4only` (the empty-family negative: a daemon configured
with `ipv4_unicast` only against dual-stack stubs, expected to fail at
establishment). Each cell contains:

- `reloadstall.log` — harness output with the historical
  `reloadstall_csv` rows and the `reloadstall_dualstack_csv` rows
  (per-family completion, gap, leading stall, withdrawal accounting,
  per-family stable markers).
- `status` — the driver's pass/fail marker.
- `rss.csv`, `vmhwm` — process RSS samples and the kernel high-water
  mark at teardown.
- `probes.csv`, `queries.csv` — operator-query latency loops.
- `provenance.json`, `quiet.tsv` — source identities and the accepted
  quiet-host samples (timing rungs only).
- `scenario/` — the generated config and both policy generations.
- `daemon.log.gz` — the daemon's JSON log.

Correctness-rung cells run without the driver carry `harness.log`,
`daemon.log.gz`, and `scenario/` only, and say so in their `NOTE`.
