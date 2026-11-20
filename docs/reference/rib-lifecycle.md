# RIB lifecycle

> **Document class: REFERENCE.**

Follow a session and its routes through the RIB, stage by stage, and see which path each session shape takes and how much of it has been measured.

The RIB is one task. It owns every received route, the best paths and
everything advertised, and it does one thing at a time. So the useful
question about any operation is: how long is the longest single turn, and
what waits behind it? The answer depends on the shape of the session. This
page gives it per shape and per stage.

It describes `main` after v0.83.0, read from the code in November 2026.
rustbgpd is public alpha overall; nothing here is a compatibility promise.
The [stability guide](stability.md) says which route-server and
route-reflector surfaces carry the narrow v1 contract and which families
(EVPN beyond scoped reflection, VPN FlowSpec, the Linux dataplane) stay
alpha. If this page and the code disagree, the code is right.

## Shape by stage

Read a row for your session shape. Each cell names the longest unit of work
at that stage.

- **paced**: the work is split into bounded turns *and other peers' updates
  run between them*. A named test or a public receipt shows it.
- **bounded turns**: the work is split into turns, and readiness probes are
  answered between them, but other peers' updates stay queued until the
  whole operation (or the stated part of it) finishes. Splitting work into
  turns is not the same as admitting unrelated input.
- **one turn**: one RIB turn that grows with the table (or with the routes
  of the peer or receiver involved). Every peer's updates, operator reads
  and timers wait behind it. Readiness probes are still answered at
  checkpoints inside it.
- **not measured**: no public receipt covers this shape at this stage. The
  path is from the code; its duration is unknown.

Turn sizes named on this page (1,024 routes, 8 or 16 members, 25 ms) are
strides and budgets checked between units of work, not hard caps. A turn
finishes the unit it is in, and one unit can be a whole table.

| Shape | [Session comes up](#session-comes-up) | [Steady state](#steady-state) | [Receiver falls behind](#receiver-falls-behind) | [Refresh, ORF, RTC](#refresh-orf-and-rt-constrain) | [Policy change](#policy-or-config-change) | [Restart](#restart) | [Session ends](#session-ends) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Plain unicast, grouped | Table build **paced** ([receipt](../perf/first-group-build-registration-2026-11.md)); initial table **one turn** | **paced** by read gate and window | Resync **one turn** per member | **one turn** per request; queued requests share it | **bounded turns**: updates held until commit; two snapshot turns | **paced** between batches; input held inside a batch | **one turn** |
| Export policy | Table build and initial table together in **one turn**; not measured | As plain | As plain | As plain | As plain | As plain; not measured with policy | One turn |
| Configured role | As export policy; not measured | As plain; not measured | As plain; not measured | As plain; not measured | As export policy; not measured | As plain; not measured | One turn; not measured |
| Route-server per-client best | Table build and own initial table together in **one turn**; not measured | Window; per-client ranking not measured | As plain; not measured | One turn per request, never shared | Shared cohort **one turn**; other members **paced** by command; not measured | **paced** between batches, as plain; a crowded prefix alone | One turn; not measured |
| Kept private: ORF, ORR, conditional advertisement, peer-context policy, slow-peer isolation | Initial table **one turn** per receiver; not measured | Window; work grows with receivers | **paced** row cursor; fallback resync one turn | One turn per request | Members **paced** by command, a whole-table resync each; not measured | **paced** row cursor | One turn |
| Add-Path send | As kept private; not measured | As kept private | As kept private; not measured with several paths | One turn per request | As kept private | As kept private; not measured with several paths | One turn |
| Dual-stack (IPv4 and IPv6 unicast) | As its row above; one table holds both families | As its row above | As above, per family | Per family | As its row above | Each family released separately | One turn covers both |
| Unicast plus EVPN or VPN | Table build and initial table together in **one turn**; not measured | EVPN fanout in **bounded turns**; later input waits for it | EVPN **paced** cursor; VPN whole family, one turn | One turn; RT change walks the group VPN table | Members **paced** by command; not measured | Unicast as plain; VPN and EVPN selection one turn | One turn |
| Labeled unicast | Initial table one turn; not measured | One message at a time; not measured | Whole family, **one turn**, outside credit | One turn; not measured | Members **paced** by command; not measured | Whole family, one turn per receiver; not measured | One turn; not measured |
| Group member holding a private family | Private family built in the initial-table turn | Private family staged per receiver | EVPN cursor; far behind: two walks of the group table | As the family's row | Members **paced** by command; not measured | Private family follows from the resync ticks | One turn |

How to read the rows:

- **Grouped** sessions share one staged table per update group. A session
  is grouped when its export result is the same as its group's for every
  route: same export-chain content, same eBGP or iBGP and reflector-client
  status, same role, same families
  ([`GroupKey`](../../crates/rib/src/manager/update_groups.rs)).
- **Kept private** sessions hold their own unicast Adj-RIB-Out although
  their families could be shared. The classifier
  ([`classify_update_group`](../../crates/rib/src/update.rs)) keeps a
  session out of every group, in this order of precedence, when:
  - its export policy reads the peer (peer-context policy);
  - it sends Add-Path (its own row, because it holds several paths per
    prefix);
  - it has per-client best together with VPN or RT-Constrain (per-client
    best on unicast alone is grouped: its own row);
  - it has an ORR vantage (optimal route reflection);
  - it has an ORF installed by the peer;
  - it has conditional advertisements attached.

  Slow-peer isolation is decided at run time, not by the classifier: with
  `slow_peer_isolation` set, a group member flagged slow is taken out of
  its group and kept private until the flag clears (`no_policy_group_key`
  in [`membership.rs`](../../crates/rib/src/manager/update_groups/membership.rs)).
  All of these read the kept-private row.
- **Group member holding a private family** is a different case: a session
  that shares unicast with its group while it also negotiated a family the
  RIB never shares. EVPN, labeled unicast, FlowSpec, BGP-LS and
  RT-Constrain rows are always held per receiver, even for a group member.
  Groups share IPv4 and IPv6 unicast and VPN.
- The row-cursor tests use single-path private receivers. An Add-Path
  receiver takes the same cursor, keyed by prefix, and has not been
  measured on its own.
- Rows combine. A dual-stack route-server client with export policy reads
  the export-policy row (and the per-client-best row if that is set), with
  the dual-stack row for what is per family.

What backs each **paced** and **bounded turns** mark:

- *Comes up, plain unicast.* The
  [first-group build receipt](../perf/first-group-build-registration-2026-11.md),
  and the work counts in tests named under
  [Session comes up](#session-comes-up). At 1M routes, during the first
  policy-free plain-unicast group build, unrelated UPDATE latency fell from
  2,209 ms to 0.60 ms. Sessions with export policy, a configured role,
  per-client-best, or mixed families can still take the synchronous build
  path. The receipt covers the build only; the initial table that follows
  is still one turn.
- *Steady state.* The read-gate test named under
  [Steady state](#steady-state) and the window thresholds. It bounds the
  input ahead of another peer's update, not the cost of one pass.
- *Falls behind, row cursor.* `a_whole_family_debt_drains_in_bounded_steps`,
  `a_step_is_at_most_one_chunk_of_keys` and
  `a_cursor_drain_is_charged_and_takes_no_operation` in
  [`tests/owed_row_cursor.rs`](../../crates/rib/src/manager/tests/owed_row_cursor.rs);
  for EVPN, `an_evpn_debt_drains_in_bounded_steps` in
  [`tests/owed_evpn_cursor.rs`](../../crates/rib/src/manager/tests/owed_evpn_cursor.rs).
  Work counts, not timings. The cursor runs from the resync tick, and route
  input is served between ticks.
- *Policy change, clean cohort: bounded turns.*
  [ADR-0105](../adr/0105-grouped-export-policy-transition.md) and its
  [receipt](../perf/prestaged-transition-inventory-2026-10.md): 700 peers
  with export policy, 400,400 prefixes. While the transition is pending
  the actor serves readiness at every poll and a bounded number of reads
  between the polls before commit; route input, timers and resync work
  stay queued until the commit finishes or the transition falls back
  (`run_actor` in [`manager/mod.rs`](../../crates/rib/src/manager/mod.rs)).
- *Policy change, members paced by command.*
  `paced_reload_matches_the_per_peer_reference_with_route_chunks_between_steps`
  and `paced_budget_admits_exactly_while_the_predicted_turn_fits` in
  [`tests/evpn_policy_pacing.rs`](../../crates/rib/src/manager/tests/evpn_policy_pacing.rs).
  Ordering and work counts on an EVPN shape; no timing for any shape.
- *Restart, grouped unicast and per-client best.* The tests named under
  [Restart](#restart). Work counts; no public timing.
- *Restart, private receivers.* The selection-release entry in
  [known issues](known-issues.md): 150 private receivers, 150,000 rows, in
  the transport harness.

### Worked example: a route-server client joins a 1M-route table

A dual-stack route-server client with an export policy reaches Established
while the Loc-RIB holds one million best routes.

1. **Registration is queued.** With 10,000 or more best routes and other
   input waiting, the RIB finishes the queued route input first. Under a
   sustained feed the client waits for the queue to empty.
2. **Its group table may have to be built, inside the registration
   turn.** Group identity includes the content of the export chain. If no
   established client has the same chain and profile, this client is the
   first member and the RIB builds the group's table from the whole
   Loc-RIB, both families, with export policy evaluated per route. The
   paced build does not apply: it covers only sessions with no export
   policy, no role, no route-server control and no per-client best.
3. **Its initial table follows in the same turn.** Without returning to
   its queues, the RIB replays the group table to the client, less the
   client's own routes, as one whole-table operation, then sends
   End-of-RIB for each family. If the group is plain (not per-client
   best), up to 64 queued joiners of the same group share one replay. A
   per-client-best joiner always gets its own.

   Build and replay are two phases of one blocking registration turn, so
   every other peer's updates wait for their sum. It grows linearly with
   the table. The 1M-route cost of this join is **not measured** for this
   shape in any public receipt. The nearest measurement is of a different
   shape: before the paced build, a plain IPv4 session with no policy held
   the actor for about 2.2 s at one million routes, build and replay
   together
   ([receipt](../perf/first-group-build-registration-2026-11.md)). Policy
   evaluation and a second family add to that by an amount nobody has
   measured.
4. **From then on it is a group member.** A changed prefix is evaluated
   once for the group, not once per client.

What has been measured, and at what shape:

- The shared replay: 50 simultaneous rejoins on a 700-member IPv4 route
  server with 400,400 prefixes, group table already built
  ([receipt](../perf/join-cohort-converged-rejoin-2026-10.md)).
- New members joining a 702-member dual-stack route server with export
  policy and 200,200 prefixes per family: a pass against a 60-second
  complete-export limit, not a turn-length measurement
  ([receipt](../perf/ixp-membership-churn-qualified-2026-09.md)).
- The paced build, for the plain shape only: one iBGP route-reflector client,
  IPv4 unicast, no export policy, at 400,000 and 1,000,000 routes in an
  in-process harness
  ([receipt](../perf/first-group-build-registration-2026-11.md)). The
  initial table after the build was still one turn of 1.3–1.4 s at one
  million routes.
- Nothing public at one million routes for a client with export policy,
  a role or per-client best.

## Overview

```mermaid
flowchart TD
    S["Peer sessions"] -->|"route input, read gate"| P["Primary queue"]
    A["API and operator reads"] --> Q["Query and readiness lanes"]
    P --> R["RIB actor, one task"]
    Q --> R
    R --> I["Adj-RIB-In, one per peer"]
    I --> L["Loc-RIB, best paths"]
    L --> G["Update group tables, shared"]
    L --> O["Private Adj-RIB-Out, one per receiver"]
    G --> C["Outbound channel, one per session"]
    O --> C
    C --> W["Session writer and TCP"]
```

Sessions and the API feed one actor through separate queues; the actor
owns the received routes, the best paths and both kinds of advertised
table, and hands updates to each session over a bounded channel.

- **Primary queue.** Route input, session up and down, End-of-RIB,
  refresh requests and commands, served in arrival order. One bounded
  channel, 4,096 entries by default.
- **Query, summary and readiness lanes.** Operator reads have their own
  lanes ([ADR-0132](../adr/0132-operator-read-path.md)). The readiness
  lane is also served at checkpoints inside long turns, so a liveness or
  readiness probe is answered while route updates wait.
- **Resync tick.** A timer that retries receivers whose channel was full
  and delivers owed rows. It fires 10 ms after some receiver has owed
  rows the tick can run, including when a slower one-second deadline was
  already armed, and every 10 ms while such a backlog remains. That is how
  the RIB notices returned credit, which arrives without a message. Other
  retry work waits one second. A tick checks a 25 ms budget between units of work. That is a
  budget, not a bound: each kind of work takes at least one unit per tick,
  and one unit can be a whole-table resync of one receiver. Test:
  `owed_keys_follow_returned_credit_within_one_backlog_tick` in
  [`tests/outbound_owing.rs`](../../crates/rib/src/manager/tests/outbound_owing.rs).
- **Background owners.** A paced group build, a restart release (between
  its batches) and a policy pre-stage each take alternate turns with the
  primary queue.

The loop is `run_actor` in
[`manager/mod.rs`](../../crates/rib/src/manager/mod.rs). The
[architecture page](../explanation/architecture.md#runtime-model) shows
where this actor sits among the daemon's other tasks.

## Session comes up

```mermaid
flowchart TD
    U["Session reaches Established"] --> W["Large, busy table: wait for queued input"]
    W --> J["Register"]
    J -->|"grouped"| E["Join update group"]
    J -->|"private"| V["Own table, one turn"]
    E --> F["First member: build group table"]
    F --> N["Plain unicast: paced turns. Other shapes: in the replay turn"]
    N --> T["Replay group table, one turn"]
    T --> X["End-of-RIB per family"]
    V --> X
```

A new session registers at once on a quiet or small RIB and waits behind
queued input on a large busy one. A group's first member builds the group
table, in paced turns only for a plain unicast session; a later member
skips the build. Every session then gets its table in one turn, which for
every shape but the paced one is the same turn as the build.

**Registration.** The transport sends `PeerUp` with the negotiated families
and the session's outbound channel. `register_active_session` in
[`peer_lifecycle.rs`](../../crates/rib/src/manager/peer_lifecycle.rs)
completes the registration inline unless the Loc-RIB has at least 10,000
routes and the actor has queued work. Deferred registrations run one at a
time, only when no route batch or primary input is waiting.

**Group or private.** The session's negotiated state and export chain are
classified. A groupable session joins the group with its key, creating it
if needed. Any other session keeps its own Adj-RIB-Out.

**First member of a group.** The group has no table yet.

- *Paced build.* `prospective_first_group` in
  [`membership.rs`](../../crates/rib/src/manager/update_groups/membership.rs)
  admits a session that negotiated only IPv4 or IPv6 unicast and has no
  export policy, no role, no route-server control and no per-client best.
  It also refuses an iBGP non-client on a route reflector and any family
  still inside a restart selection hold.
  [`first_group_build.rs`](../../crates/rib/src/manager/first_group_build.rs)
  then builds the table privately. Each turn visits at most 1,024 Loc-RIB
  hash buckets or repairs at most 1,024 keys that changed behind the walk,
  and route input takes the turns in between. The table is published only
  when complete, so no joiner sees part of it. If more than 4,096 distinct
  keys change before the walk can repair them, the partial table is
  retired, 1,024 slots a turn, and the build starts again.
  - Tests: `registration_finishes_discovery_and_repairs_under_continuing_changes`
    and `registration_coalesces_repairs_and_invalidates_on_the_first_excess_key`
    in [`loc_rib.rs`](../../crates/rib/src/loc_rib.rs) bound a turn's work;
    `imports_during_unpublished_build_reach_both_joiners_before_eor` in
    [`tests/first_group_build.rs`](../../crates/rib/src/manager/tests/first_group_build.rs)
    shows updates installing during a build.
  - Measured: at 1M routes, during the first policy-free plain-unicast
    group build, unrelated UPDATE latency fell from 2,209 ms to 0.60 ms.
    Sessions with export policy, a configured role, per-client-best, or
    mixed families can still take the synchronous build path
    ([receipt](../perf/first-group-build-registration-2026-11.md): one
    iBGP route-reflector client, IPv4 unicast, in-process harness, one
    concurrent UPDATE).
  - Not measured: a build under sustained input above the repair rate,
    which can restart repeatedly.
- *One-turn build.* Every other grouped session takes `ensure_group_table`:
  a walk of the whole Loc-RIB that stages every family the group owns.
  That includes every session with export policy, a role, route-server
  control or per-client best, and any session that also negotiated VPN,
  EVPN or another non-unicast family. It runs inside the registration
  turn: `install_registration_state` reaches it through `join_group`, and
  the initial table below follows without the actor returning to its
  queues (`complete_deferred_registration`). Other peers wait for the
  build and the replay together. Not measured for those shapes.

**Initial table.** `send_initial_table` replays the group table (or, for a
private receiver, walks the Loc-RIB) and commits the result in one turn:
its own turn after a paced build, the registration turn otherwise. It is
a whole-table operation: one per peer at a time, not charged against the
receiver's row credit ([`outbound_credit.rs`](../../crates/rib/src/outbound_credit.rs)).
Private families (EVPN, labeled unicast and the rest) are built in the same
turn. End-of-RIB for each family follows its routes.

- Queued joiners of one plain group share a replay: up to 64 registrations
  complete in one turn from one payload (`take_join_cohort`). Per-client
  best groups and sessions with Add-Path, ORF, ORR or conditional
  advertisement do not share.
- Measured: the shared replay at 700 IPv4 route-server members and 400,400
  prefixes ([receipt](../perf/join-cohort-converged-rejoin-2026-10.md)).
  A full-table ROUTE-REFRESH replay of one family, which uses the same
  group replay, held the actor for 211–246 ms at 700 route-server peers
  and 400,400 IPv4 prefixes
  ([receipt](../perf/route-refresh-readiness-2026-10.md)).
- Not measured: the initial table at one million routes, for any shape.
  Splitting it into bounded turns is not on main.

## Steady state

```mermaid
flowchart TD
    A["Peer sends UPDATE"] --> B["Session decodes, applies import policy"]
    B --> C{"1,536 of its routes unfinished in the RIB?"}
    C -->|"yes"| D["Stop reading the socket until 1,024"]
    C -->|"no"| E["Primary queue"]
    D --> E
    E --> F["Adj-RIB-In and best path, 1,024 routes a chunk"]
    F --> G["Window closes, one distribution pass"]
    G --> H["Group: stage once per prefix"]
    G --> I["Private: stage per receiver, charge credit"]
    H --> J{"Channel has room?"}
    I --> J
    J -->|"yes"| K["Session encodes and writes"]
    J -->|"no"| L["Receiver owes rows, resync tick retries"]
```

Each session's input is gated at the socket, installed in chunks, and
distributed once per window to groups and private receivers; a receiver
that cannot take an update is retried by the resync tick.

**Read gate.** A session charges every route it sends to the RIB against
its own budget and stops reading its socket at 1,536 unfinished routes,
resuming at 1,024 ([`ingest_budget.rs`](../../crates/rib/src/ingest_budget.rs),
[ADR-0078](../adr/0078-inbound-rib-backpressure.md)). One peer's burst
therefore puts about two full UPDATEs ahead of another peer's update, not
the whole burst. Test:
`unpaced_burst_leaves_at_most_two_messages_ahead_of_another_source` in
[`tests/ingest_budget.rs`](../../crates/transport/src/session/tests/ingest_budget.rs).
The wait still grows with the number of peers bursting at once, and input
that does not come from a session is not gated.

**Install and select.** A message's routes enter the peer's Adj-RIB-In in
chunks of 1,024, and best path is recomputed for the affected prefixes.
Reads and the readiness lane are served between chunks.

**Distribution window.** Unicast route input already queued is coalesced
into one window. The window stops taking messages once it holds 256
messages, 4,096 routes or 1,024 distinct prefixes, or is 5 ms old
([`DistributionWindowLimits`](../../crates/rib/src/manager/distribution/mod.rs)).
These are thresholds tested after each whole message, not maxima: the
message that crosses one is finished first, so a single 1,200-prefix
UPDATE makes a 1,200-prefix window
(`each_window_bound_splits_queued_input` in
[`tests/distribution_window.rs`](../../crates/rib/src/manager/tests/distribution_window.rs)
shows a three-route threshold producing four-route windows). They limit
how much input is coalesced, not the work or duration of the pass. The
window ends with one distribution pass over its affected prefixes. EVPN
and FlowSpec input never joins a window; VPN and labeled unicast arrive as
their own messages. Each of those is distributed message by message.

**Groups.** For each group and changed prefix the export gates and policy
run once. Members get the shared result, each less its own routes
([ADR-0099](../adr/0099-update-groups-v2.md); encode sharing in
[ADR-0109](../adr/0109-update-group-shared-encode.md); per-client best in
[ADR-0126](../adr/0126-shared-group-per-client-best.md)).

**Private receivers.** The same pass stages each private receiver in turn,
so its cost grows with receivers times changed rows. Two known waits
remain on main.

- *EVPN fanout: bounded turns, not one turn.* An inbound EVPN chunk is
  committed to every private receiver. Once the 25 ms flush budget is
  spent the fanout parks at a receiver boundary and the next turn serves
  the next receivers (`recompute_and_distribute_evpn_paced` in
  [`distribution/evpn.rs`](../../crates/rib/src/manager/distribution/evpn.rs);
  test `evpn_inbound_fanout_parks_at_receiver_boundaries` in
  [`tests/evpn.rs`](../../crates/rib/src/manager/tests/evpn.rs)). Readiness
  is served between those turns. Later route chunks and messages, from
  every peer, still wait until every receiver has the chunk, so the wait
  of an unrelated update grows with receivers
  ([known issues](known-issues.md)).
- *Trie growth: one turn.* A unicast advertised table moves memory in
  proportion to its size when its prefix index doubles: 4 bytes per trie
  cell and 16 bytes per node slot
  ([`adj_rib_out.rs`](../../crates/rib/src/adj_rib_out.rs)). That cost has
  a work count in a unit test and no timing.

**Credit and channel.** An update toward a private receiver is admitted
only while the receiver's unsent private rows are under its row credit: a
daemon-wide 16,777,216 rows divided among registered peers, between 8,192
and 1,048,576 each. A refused or full channel never blocks the RIB. The
receiver is marked as owing and the resync tick retries it
([Receiver falls behind](#receiver-falls-behind)).

**Wire.** The session builds UPDATEs from the handed-over routes
(AS_PATH, NEXT_HOP, the negotiated encodings) and its writer sends them.
The writer's queued bytes are bounded
([receipt](../perf/writer-byte-budget-2026-11-07.md)).

What "paced by read gate and window" in the matrix rests on: the read gate
test above and the window thresholds. No public receipt times an unrelated peer's wait at a
stated receiver count on main; the figures in known issues are single
untimed harness runs and say so.

## Receiver falls behind

When a receiver's channel is full or its credit is spent, the RIB records
which rows it is owed and the resync tick delivers them later; this
section, with the row cursor, eviction and resync in full, is the next
addition to this page. Until then see the
[Falls behind column](#shape-by-stage), the module doc of
[`outbound_owing.rs`](../../crates/rib/src/manager/outbound_owing.rs) and
[known issues](known-issues.md).

## Refresh, ORF and RT-Constrain

A ROUTE-REFRESH answer, an ORF change and a route-target membership change
each resend part of a table to one receiver; each answer is one
whole-table operation today, and compatible queued refreshes of one plain
group share a replay
([receipt](../perf/shared-route-refresh-2026-10-11.md), 200-peer IPv4 route
reflector, 400,000 prefixes). The full section is still to be written; see
the [Refresh, ORF, RTC column](#shape-by-stage).

## Policy or config change

An export-policy change moves sessions between update groups, by one of
three paths.

- **Clean cohort: bounded turns.** A clean, unicast-only, single-best
  cohort moves as one transaction split into actor polls
  ([ADR-0105](../adr/0105-grouped-export-policy-transition.md);
  [receipt](../perf/prestaged-transition-inventory-2026-10.md), 700 peers,
  400,400 prefixes). A poll works in strides of 1,024 routes or eight
  members and keeps taking strides until a nominal 25 ms budget is spent,
  so several strides can run in one poll
  (`commit_flush_uses_full_poll_budget_before_parking` in
  [`tests/update_groups.rs`](../../crates/rib/src/manager/tests/update_groups.rs)).
  The strides are not caps on a poll. Whole-table work remains in three
  places: two snapshot turns, and the last commit poll, which also runs
  one distribution pass that retries every peer still owed updates for
  any other reason. From the first poll to the commit or the fallback,
  route input, timers and resync work stay queued; readiness is answered
  at every poll, and a bounded number of reads between the polls before
  commit. Other peers' updates therefore wait for the whole transition,
  in bounded turns.
- **Shared cohort in one turn.** A cohort the clean path refuses goes to
  one authoritative batch command. Members that can still move together
  commit inside that one turn. That includes a whole per-client-best
  group moving to one new chain, which shares one payload and takes no
  per-member resync
  (`batched_authoritative_pcb_cohort_commits_in_one_shared_transition` in
  [`tests/update_groups.rs`](../../crates/rib/src/manager/tests/update_groups.rs)).
  Not measured.
- **Remaining members, paced by command.** Every other changed member
  (ungrouped, per-client best outside a shared cohort, or sending EVPN,
  VPN, labeled unicast, FlowSpec or BGP-LS) is handed back, and the peer
  manager applies them a few per command (`walk_paced_export_policies` in
  [`policy.rs`](../../src/peer_manager/policy.rs)). A command takes as
  many members as are predicted to fit 250 ms and always at least one;
  each member's move is a resync of its whole table, so one heavy member
  can exceed the budget. Other RIB work, route input included, runs
  between commands
  (`paced_reload_matches_the_per_peer_reference_with_route_chunks_between_steps`
  in
  [`tests/evpn_policy_pacing.rs`](../../crates/rib/src/manager/tests/evpn_policy_pacing.rs)).
  Not measured at any stated scale.

The full section is still to be written; see the
[Policy change column](#shape-by-stage) and the
[reload matrix](reload-matrix.md).

## Restart

After a planned restart the RIB holds route selection until its restarting
peers send End-of-RIB or the deferral timer expires (RFC 4724), then
releases each family. IPv4 and IPv6 unicast release in batches of at most
1,024 prefixes, each delivered to 16 group members a step
(`one_release_poll_admits_only_a_bounded_page_of_group_members` in
[`tests/paced_selection_release.rs`](../../crates/rib/src/manager/tests/paced_selection_release.rs)).
Route input and timers are admitted between batches, not while a batch
is being delivered
(`input_queued_mid_release_precedes_the_last_batch_and_its_marker`, same
file). So the release is paced between batches and runs in bounded turns
inside one.

A per-client-best group releases the same way on main. Its prefixes are
ranked in bounded steps, staged together as one group delta, and sent to
16 members a step. A stage holds prefixes of one batch and closes at
2,048 work units, one for each prefix and one for each of its denied or
control-community-suppressible candidates, so a batch with no such
candidate is one message and a batch that carries them is several. A
prefix with more than 128 denial and fallback rows is the exception: it
keeps the older path and is released on its own. The evidence is work
counts and exact-table checks in tests; there is no public timing
receipt:

- `a_per_client_best_release_batch_is_not_paged_by_prefix_times_member`,
  `a_denial_heavy_per_client_best_batch_is_staged_in_bounded_parts` and
  `per_client_best_release_matches_the_ranking_for_every_client` in
  [`tests/paced_selection_release.rs`](../../crates/rib/src/manager/tests/paced_selection_release.rs).
  The first pins that a per-client-best batch holds input for no more
  polls than an ordinary group's batch plus its ranking steps.
- `a_stage_closes_when_its_work_reaches_the_cap`,
  `one_release_poll_examines_one_page_of_candidates_across_prefixes` and
  `crowded_fallback_and_denial_lists_release_exact_tables` in
  [`tests/paced_selection_release/per_client_best_release.rs`](../../crates/rib/src/manager/tests/paced_selection_release/per_client_best_release.rs).

The full section is still to be written; see the
[Restart column](#shape-by-stage).

## Session ends

```mermaid
flowchart TD
    A["Session ends: down, or graceful restart"] --> B{"Paced group build holds a policy change for this peer?"}
    B -->|"no"| D["Teardown turn"]
    B -->|"yes"| C["End waits in an ordered window of eight"]
    C -->|"policy change commits"| D
    D --> E["Collect the peer's route keys"]
    E --> F["Recompute best path, distribute withdrawals"]
    F --> G["Drop outbound state, leave the group"]
    G --> H["Retire tables, collect attributes"]
```

A session end normally runs at once as one turn sized by the peer's routes;
behind a paced group build that holds a policy change for the same peer it
waits, in order, while other peers' route input keeps flowing.

**Which end.** A plain `PeerDown` removes the peer's routes. A graceful
restart end keeps them as stale and starts the restart timer instead
([architecture](../explanation/architecture.md#graceful-restart-receiving)).
An end from a session that a newer session of the same peer replaced is
discarded, and an end of the active session while a second live session
remains fails the registration over to the survivor
(`handle_peer_down` and `classify_session_teardown` in
[`peer_lifecycle.rs`](../../crates/rib/src/manager/peer_lifecycle.rs)).

**The teardown turn.** `peer_down_teardown` does all of this in one turn:

1. Collects every key the peer announced, in every family.
2. Recomputes best path for those keys and runs one distribution pass, so
   withdrawals and replacement routes go out to every other peer.
3. Drops the peer's outbound state: its owed rows, its private Adj-RIB-Out,
   its group membership. If it was the last member, the group's table is
   retired in the same turn.
4. Frees the peer's Adj-RIB-In and collects unused attributes.

The turn grows with the routes the peer announced, plus the table it was
sent if that table is retired. A peer that announced a full table is a
table-sized turn. The readiness lane is served at checkpoints throughout;
route updates, operator reads and timers wait.

- Measured: readiness during the cleanup phases, removing 1,230,000 keys
  on a hosted VM. Unicast: longest gap between checkpoints under 2 ms,
  in-process readiness replies within 50 ms. VPN: under 10 ms and within
  82 ms
  ([receipt](../perf/peer-teardown-cleanup-readiness-7ff33596-2026-10-16.md)).
  That receipt times cleanup, not the recompute and withdrawal pass.
- Tests: `peer_down_burst_work_is_linear` in
  [`tests/work_scaling.rs`](../../crates/rib/src/manager/tests/work_scaling.rs)
  pins that a burst of session ends does work linear in the group's size,
  not members times withdrawals.
- Not measured: how long an unrelated peer's update waits behind the end
  of a full-table peer, at any shape.

**What waits behind it.** Normally nothing waits on a session end; it runs
when it reaches the head of the primary queue. The exception is a paced
first-member build with a claimed export-policy change:

- A policy change that needs the table under construction is parked until
  the table is ready. A session end for a peer that change names must run
  after it. The end is kept in an ordered window of at most eight commands
  and session ends, and runs right after the policy change commits
  ([`first_group_order.rs`](../../crates/rib/src/manager/first_group_order.rs)).
- While it waits, only unicast, labeled-unicast, VPN and EVPN route input
  from other peers passes it. End-of-RIB, FlowSpec, BGP-LS and
  RT-Constrain input, operator reads on the primary queue, commands,
  other session changes and the same peer's later messages all wait for
  the rest of the build.
- The queue is held completely, as before, when a ninth command or end
  arrives, when a stale-route or refresh timer falls due, or when passing
  input overflows the build's repair log.
- While the end waits the peer's routes stay selected and advertised.
- Tests: `unrelated_update_passes_a_session_end_that_waits_for_the_cold_build`,
  `only_plain_route_input_from_another_peer_passes_a_retained_session_end`
  and `full_window_holds_the_ninth_session_end_at_the_head` in
  [`tests/first_group_build.rs`](../../crates/rib/src/manager/tests/first_group_build.rs).
- Not measured: the length of the hold at 400,000 or 1,000,000 routes, or
  with periodic primary-queue reads (BMP statistics, EVPN dataplane
  queries) that re-hold the queue. A mass disconnect during a build
  exceeds the window of eight and holds the queue.

## Invariants

The invariants the RIB keeps across these stages, and the tests that pin
each, will be listed here with the remaining stages. Two are already
stated above: a group table is never visible while partly built, and a
family's End-of-RIB never precedes the routes it covers.
