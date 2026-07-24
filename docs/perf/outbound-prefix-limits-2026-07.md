# ADR-0113 outbound prefix-limit real-session receipt — 2026-07

This receipt answers one bounded question: do the configured outbound unicast
prefix maxima actually bound what leaves the real encoder, on the shared
update-group fanout as well as the private per-peer path? Four real BGP
sessions exchange real OPEN/KEEPALIVE/UPDATE messages with a real rustbgpd
over loopback, and the wire-side prefix counts at each observer are the
answer.

It is a behavior receipt, not a timing one. There is no host-quiescence
preflight, no distribution is collected, and no performance claim follows from
it.

**Verdict: green at the measured commit.** The caps bound the wire on both
distribution paths, a lowering below current usage is rejected atomically with
wire state intact, a raise delivers the withheld prefixes on both paths
without touching the unlimited sibling and without resetting a session, the
operator-visible surfaces agree with the wire in the same snapshot, and the
episode logging is bounded as specified. No session was reset by either limit
edit, including the one made on the peer group.

**Measured commit:** `e2e66fb75e0565c6b3282bef0020744f05b160dc`

**Result:** 96 of 96 precommitted checks pass (91 harness checks, 0 failed;
5 driver log gates, 0 failed). Zero stub decode errors on daemon UPDATEs.

An earlier run of this same scenario was red at 79 of 96. Every failure was
one defect: a peer-group edit reshaped (delete + re-add) each inheriting static
member, so the group-level maxima edit — the path an IX operator would
actually use — tore down the capped member's session before recovery could be
observed. That reshape is now partitioned by impact class, and an all-`live`
group edit applies in place; the checks that could not be made are made below.

## Disclosed shape

The shape is pinned in the harness as constants, so this section describes the
run that was performed rather than a configurable intent.

| | |
|---|---|
| Peers | 4 real BGP sessions (1 route source, 3 observers) |
| Families | IPv4 unicast and IPv6 unicast; nothing else negotiated |
| Add-Path | **not negotiated on any session** |
| Table | 12 IPv4 `/24`s + 6 IPv6 `/64`s, originated by one source peer |
| Starting maxima | `max_prefixes_out_ipv4 = 8`, `max_prefixes_out_ipv6 = 4` |
| Rejected candidate | `2` / `1` — below current usage, must be refused whole |
| Raised maxima | `12` / `6` — exactly enough for the full table |
| Local ASN | `65500`, all peers eBGP with distinct remote ASNs |
| Export policy | none configured (so the update-group key is not policy-split) |

| Peer | Role | Maxima come from | Distribution path |
|---|---|---|---|
| `127.9.0.1` | route source | -- | grouped |
| `127.9.0.2` | peer-group member, sets no maxima of its own | **peer group** | **grouped** |
| `127.9.0.3` | unlimited sibling | -- | grouped |
| `127.9.0.4` | RFC 7947 per-client-best peer | neighbor | private |

Add-Path is disclosed as absent for a structural reason, not an oversight:
Add-Path *send* disqualifies update-group membership, so one session cannot
exercise both the grouped fanout and RFC 7911 path-identifier slot sharing.
This receipt covers the grouped fanout; the Add-Path slot-sharing rule stays a
unit-level contract and **is not proved here**.

The unlimited sibling is the non-vacuity sentinel. Until it holds all 18
prefixes, "the capped peer received only 8" would be indistinguishable from
"only 8 were ever distributed".

## What holds

| Precommitted check | Result |
|---|---:|
| Sessions established | 4 / 4 |
| Cold convergence (sibling holds the full table) | 0.052 s (single observation, not a distribution) |
| IPv4 / IPv6 prefixes on the wire at the **grouped capped** peer | 8 / 4 (cap 8 / 4) |
| IPv4 / IPv6 prefixes on the wire at the **unlimited sibling** | 12 / 6 |
| IPv4 / IPv6 prefixes on the wire at the **private capped** peer | 8 / 4 (cap 8 / 4) |
| Withdrawals sent to either capped peer | 0 |
| `bgp_peer_update_group` for capped / sibling / private | 1 / 1 / -1 |
| `bgp_update_group_fallback_peers` | 1 |
| `bgp_update_group_regroups_total` across the whole run | 0 |
| Blocked-attempt counters at the capped member (v4 / v6) | 4 / 2 |
| Capacity gauges vs. the neighbor API, capped peers, both families | agree in every scrape |
| Capacity gauges at the unlimited sibling | `usage` 12 / 6, no `limit` or `headroom` series |
| `rbgp rib advertised` at the grouped capped member (v4 / v6) | 8 / 4 — the admitted set, not group intent |
| Lowering below usage | rejected whole, naming all four peer/family violations |
| Wire, admitted set, and running maxima after the rejected lowering | unchanged |
| Sessions reset by the rejected lowering | 0 |
| **Raise on the grouped path: IPv4 / IPv6 on the wire** | **12 / 6** |
| **Raise on the private path: IPv4 / IPv6 on the wire** | **12 / 6** |
| Time from the raising SIGHUP to the capped member holding the full table | 1.027 s (single observation) |
| Churn the raise caused at the unlimited sibling | 0 announcements, 0 withdrawals |
| Sessions reset across the whole block/recovery arc | 0 |
| Peer teardowns across the two limit-only edits | 0 |
| Blocking-episode openings / recoveries in the log | 4 / 4 |
| Stub decode errors on daemon UPDATEs | 0 |

### The grouped assertion, and exactly what it proves

ADR-0113 singles this out because a limit implemented by quietly pushing the
constrained member onto a private path would look identical on the wire. Three
independent surfaces agree that it did not:

- `bgp_peer_update_group{peer="127.9.0.2"}` and `{peer="127.9.0.3"}` both read
  `1` while the capped member is blocking. The gauge's `-1` sentinel is
  reserved for the private path, and the per-client-best peer reads exactly
  that.
- `rbgp neighbor 127.9.0.2 --compare 127.9.0.3` returns
  `verdict: shared`, `primary_membership: grouped`,
  `comparison_membership: grouped` — the operator-visible form, which never
  exposes an internal group id. The same command against the private peer
  returns `verdict: private`, `comparison_membership: per_client_best`.
- The sibling received all 12 IPv4 and all 6 IPv6 prefixes while sharing that
  group with a member that was withholding 4 and 2. The shared payload was
  therefore not filtered down to the constrained member, and
  `bgp_update_group_regroups_total` stayed at 0 for the whole run.

Its limits: this proves shared *membership* and an unfiltered shared payload
for a two-member group over one export-policy profile. It does not prove
anything about grouped behavior at fanout scale, under Add-Path, under policy
that is peer-context-sensitive, or for non-unicast families.

### The recovery assertion, and exactly what it proves

A raise re-advertises intent the limiter never inventoried, so recovery has to
re-derive the family from current Loc-RIB and group state. Both distribution
paths are now observed end to end in the same window.

On the **grouped** path the maxima are raised on `[peer_groups.capped-clients]`
and reach `127.9.0.2` purely by inheritance. Every field the edit changes is
reload-matrix `live`, so the reload applies the group in place — the daemon
logs `hot-applied peer-group change in place (no session reshape)` with
`members=1` and never logs a `peer deleted` — and the member's session, TCP
connection, and FSM are untouched. 1.027 s after the SIGHUP the withheld 4
IPv4 and 2 IPv6 prefixes arrive on that session with no withdrawal, the gauges
move to 12 / 6 with `blocking` back to 0, `rbgp rib advertised` reports 12 / 6,
`rbgp neighbor -j` drops the blocking reason, and the member is still in the
same update group (`bgp_update_group_regroups_total` still 0).

On the **private** path the same arc holds for `127.9.0.4`, whose maxima come
from its own `[[neighbors]]` row (`reload: neighbor hot-applied in place`, no
session rebuild): gauges to 12 / 6 and all 18 prefixes on the wire.

Both families on both limited peers log exactly one
`outbound prefix limit recovered`, four in total, matching the four openings.
The unlimited sibling saw no announcement and no withdrawal across the same
window, so neither resync leaked outside its target.

Its limits: one raise, from one starting cap, on a two-member group with 18
prefixes. It says nothing about the cost of the transient O(table) recovery
scan at a real table size, and it does not exercise a partial raise that leaves
a family still blocking.

## What this receipt does not cover

Stated as plainly as what it does:

- **Add-Path.** Not negotiated anywhere. The rule that every path identifier
  for one NLRI shares a single slot is not exercised.
- **Scale.** Four peers and 18 prefixes. Nothing here speaks to fanout cost,
  the O(limit) grouped memory exception, or the transient O(table) recovery
  scan. This receipt publishes no timing distribution — the two elapsed numbers
  it does report are single observations from one run, not medians.
- **Repetition.** One run, on one host, at one commit. No distribution, no
  confidence interval, no cross-host comparison.
- **Regroup handoff.** No peer moves between the grouped and private paths
  while limited, so ADR-0113's private-to-grouped ownership transfer is not
  exercised end to end.
- **The persisted config-transaction path.** Only the startup and SIGHUP
  paths are driven. The prepared/inactive transaction, its activation
  idempotency, commit-confirm tightening, and the ambiguous post-persist
  outcome are untested here.
- **A mixed peer-group change set.** Both SIGHUPs edit only maxima, so the
  all-`live` in-place path is the one exercised. The fallback — a change set
  that also moves a session-reset field and therefore still reshapes static
  members — is not driven here.
- **Teardown and reconnect across a blocking episode.** Gauge reaping and a
  fresh generation starting at zero are not asserted; no session is torn down
  in this run.
- **Non-unicast families.** Out of ADR scope and not configured.
- **Exact-export interaction.** No route is rejected by exact-export
  precommit in this scenario, so the "a synthesized withdrawal frees capacity
  first" ordering is not exercised.
- **CLI assertions are presence/absence, not full parse.** The exact numeric
  rows are asserted from Prometheus and from the wire; the human and JSON
  neighbor output is retained verbatim and checked for the presence or absence
  of the stable `outbound_prefix_limit_reached` reason.

## Method and gates

`bench/scale/outbound-prefix-limits/run-receipt.sh` takes no arguments and
refuses a dirty checkout, so the published rows belong to one immutable
commit. It records provenance and binary hashes, builds the daemon, CLI, and
harness with `--release --locked`, generates all three config generations and
runs each through a real `rustbgpd --check`, starts the daemon, and waits for
a real gRPC round trip before measuring.

The harness owns the four sessions for the whole run and drives every phase,
so a limit edit is observed by sessions that were already established when it
was made. Each assertion prints one `CHECK <name> <PASS|FAIL> <detail>` line.
Phase gates after cold convergence are deliberately non-fatal: a receipt that
aborts on its first failure hides the rest of the picture, which is exactly
what happened on the first run of this scenario.

Cold convergence is the only fatal wait. The driver then applies five log
gates that the harness cannot see: exactly four blocking-episode openings (two
limited peers x two families, with no per-prefix spam), exactly four
recoveries, exactly one rejected SIGHUP naming its violation, and zero peer
teardowns across two limit-only edits.

The run is accepted only when every harness check and every log gate passes.
At the measured commit it is accepted.

## Reproduce

On a Linux host with loopback addresses and ports 17900/19179 free:

```console
git checkout e2e66fb75e0565c6b3282bef0020744f05b160dc
bench/scale/outbound-prefix-limits/run-receipt.sh
```

Raw output is private and ignored under `target/outbound-prefix-limits/`:
provenance, binary hashes, the three config generations, the daemon log,
per-phase Prometheus scrapes, `rbgp` neighbor / advertised-route /
update-group-comparison output, `summary.json`, and checksums. It carries host
paths and is not published; the rows above are the sanitized result.
