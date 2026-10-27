# rustbgpd-rib

RIB data structures and best-path selection for rustbgpd.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Architecture

Single-task ownership — `RibManager` runs as one tokio task with no
`Arc<RwLock>`. All RIB mutations flow through an `mpsc` channel as
`RibUpdate` messages.

The daemon also installs a bounded `RibSummaryQuery` lane for export-policy
counters and the RIB portion of neighbor status. Synchronous policy replacement,
rollback, and dataset reevaluation answer this lane from one temporary projection
captured before their outbound-state mutations. Nested helpers reuse the same
values; after completion, reads use current actor state. On the daemon's
multi-thread runtime, one `block_in_place` scope hands the executor to sibling
tasks so completed replies can run while synchronous RIB work continues.
Current-thread embedders retain synchronous execution. Route queries and
mutations remain fenced. The projection owns numeric counters and small status
rows, not route tables or shared policy counters.

Initial table export also services the dedicated readiness lane at bounded
checkpoints through inventory, replay, staging, commit, and owned route cleanup.
The exact Loc-RIB count remains fixed because this work only changes outbound
state. The same executor handoff lets health replies complete during export;
standalone export leaves general and summary queries and mutations queued.
Nested export retains the existing owner’s frozen-summary contract, age, and
stalled-transition verdict. This covers both
initial registration and negotiated Add-Path limit replay. Family replays
take the same owner: peer ROUTE-REFRESH responses, deferred refresh retries,
outbound prefix-limit recovery and operator outbound replay.

Selection-deferral release and collision-failback staging also service readiness
through inventory, selection, outbound staging, and temporary-key cleanup. The
actor retains exclusive ownership and preserves family gate, ledger, and EoR
ordering. Unlike outbound-only replacement, unicast selection changes Loc-RIB;
readiness refreshes its exact count after each complete prefix mutation.
General and summary reads and queued mutations remain fenced until release
finishes. A release that runs longer than 30 seconds fails readiness closed
under its own `RIB selection-deferral release stalled` reason, with readiness
waits recorded under the `selection_release` seam, until the release finishes.
These checkpoints bound repeated work between probes; they are not a
universal wall-clock guarantee for arbitrary route or peer counts. Individual
best-path computations, collection allocation/sorting, and ORR topology/SPF
work remain synchronous; checkpoints do not preempt those operations.

Capture completes before summary service starts, and exact-export rejection
counts can require route-overlay scans. This mechanism does not by itself prove
a latency bound at every scale. Peer-manager/session fields in the same RPC are
independent observations; no fleet-wide atomic snapshot is implied.

### Map growth and checkpoint boundaries

Large maps with checkpointed writers use `ShardedMap`: after 16,384 entries,
an insertion grows one of 16 hash tables instead of rehashing the complete map.
The split itself moves at most 16,384 entries. This bounds the amount of data
rehash moves; it does not guarantee a fixed elapsed time for every insertion.
Maps that only fill an empty snapshot can instead reserve their known upper
bound before the walk. Retirement must retain its per-entry checkpoints.

The update-group and manager inventory has these boundaries:

| Map or set | Growth and walk handling |
| --- | --- |
| Group `source_attrs` | Sharded; both route deltas and source-tag transitions use the same writer. Passthrough groups keep the map empty. |
| Group `runner_up` | Sharded; no full-table reservation of route values for groups without exception lanes. |
| Group `policy_filtered` | Sharded outer prefix map; the existing checkpointed writer replaces each affected prefix's candidate denials. |
| Group `vpn_policy_denied` | Sharded; remove affected keys directly, then insert denials between checkpoints. |
| Route slabs (Adj-RIB-In, Adj-RIB-Out, group table) | Fixed 64Ki-slot segments: growth allocates one segment and copies at most one, so a group that joins before the feed fills without whole-table copies. The prefix trie and `Self_` flags still double inside one insert; their entries are a fraction of a route body's size. |
| Regroup snapshot `next_hop_overrides` | On the first override, reserve the table's override count plus exception-lane entries, before filling the empty map. Snapshots without overrides allocate nothing. |
| Policy-transition prestage `failed` and `tagged` | Sharded; bounded inventory slices and dirty-key reconciliation retain checkpoints, including retirement. |
| Group `inventory_log` and its dirty-key union | Logs are sharded and retire between checkpoints. The empty union reserves the union of both logs, counting keys churned in both groups once, before checkpointed insertion. |
| `ExportMemo.entries` | Sharded; full-table export callers already checkpoint per route or candidate. Distinct source attribute allocations can fill the map. |
| BoRR `refresh_stale_*` | All seven inventories are sharded. The snapshot caller holds executor/readiness ownership and checkpoints every visited input and old snapshot key, including excluded routes and retained sibling families. |
| LLGR `*_llgr_stale_local_tags` | Still requires checkpoint-aware promotion through removal, attribute mutation/interning, selection and cleanup before bounding set growth. |
| Selection-deferral identity sets | Retained identities have admission limits, but resize work is not bounded. EVPN and RTC recorders also need input checkpoints. |
| First outbound-limit admitted-set installation | The actual Apply command owns readiness through preflight, allocation, inventory fill and retirement. Each typed set reserves the shared table's distinct prefix count for its own AFI before the pre-exclusion route walk; removal retires each retained prefix between checkpoints. Regroup uses the same reserved collector. |
| `current_policy_filtered_routes` temporaries | Still require bounded set growth and missing candidate-transfer checkpoints. Prefix count alone does not bound multipath rejection identities. |

Production-writer growth regressions cover the sharded maps and the route slab
above. A build with `bench-internals` can trace source-attribute and group-table
capacity changes with `RUST_LOG=rustbgpd_rib::map_growth=trace`; each event
names the map, the before/after capacity and the write's duration. Correlate
these events with actor-turn and work-unit observations before attributing a
loaded distribution stall to a map. Passthrough groups never write
`source_attrs`, so that witness is silent for them. Full-table latency,
convergence and peak-memory qualification remain separate from the
deterministic growth checks.

## Features

- **Adj-RIB-In** — per-peer inbound route storage with stale marking
  (GR/LLGR), refresh-stale tracking (Enhanced Route Refresh), and
  per-prefix Add-Path support
- **Loc-RIB** — best-path selection per RFC 4271 section 9.1.2 with
  extensions: RPKI validation (step 0.5), ASPA path verification (step 0.7),
  stale demotion (step 0),
  deterministic MED (always-compare), route reflector tiebreakers, and a
  deterministic same-peer unicast Add-Path identity tie after all BGP criteria
- **SRv6 service eligibility** — RFC 9252 service SID structure and
  family-specific transposition checks exclude unusable candidates before
  selection, Add-Path, ORR, and ECMP, while preserving received attributes.
  Unicast and EVPN explain report `srv6_sid_invalid`; VPN received rows remain
  internal because no received-VPN query is exposed. This does not originate
  SRv6 services or install SRv6 forwarding state.
- **Adj-RIB-Out** — per-peer outbound route tracking with split horizon,
  iBGP suppression, route reflector reflection rules
- **Outbound prefix limits** — per-peer, per-family Adj-RIB-Out prefix
  ceilings with non-destructive blocking: net-new advertisements are
  held at the cap without withdrawing existing routes or resetting the
  session (ADR-0113)
- **FlowSpec** — parallel storage for FlowSpec rules (SAFI 133), with optional
  cross-RIB feasibility and retained-candidate diagnostics
- **VPN, labeled-unicast, and RT-Constrain** — parallel storage and
  distribution for VPNv4/VPNv6 (SAFI 128), labeled-unicast (SAFI 4), and
  RT-Constrain membership (SAFI 132)
- **BGP-LS and EVPN** — typed route storage, best-path selection, and outbound
  distribution for link-state and EVPN families
- **Conditional advertisement (alpha)** — advertise-if-present /
  advertise-if-absent gating of IPv4/IPv6 unicast exports to attached static
  neighbors, driven by exact condition prefixes in the Loc-RIB and enforced
  immediately before the neighbor's export policy (ADR-0137)
- **Optimal Route Reflection** — RFC 9107 BGP-LS topology, per-vantage SPF,
  and vantage-scoped next-hop cost comparison
- **Selection deferral** — RFC 4724 restarting-speaker startup gates that
  defer per-family selection until the frozen waiter roster completes or the
  configured timeout expires
- **Multi-path** — Add-Path multi-candidate distribution with
  rank-based path ID assignment
- **Graceful Restart** — stale route preservation, per-family EoR
  tracking, timer-based sweep, LLGR two-phase promotion

## Key types

- **`RibManager`** — event loop processing `RibUpdate` messages
- **`adj_rib_in::AdjRibIn`** — per-peer inbound route table
- **`Route`** — prefix + attributes + metadata (path_id, validation_state, stale flags)
- **`AttrSet`** — shared attributes and cached unicast best-path inputs; copy-on-write
  edits rebuild the cache, including when an edit unwinds
- **`best_path_cmp()`** — standalone comparison function (not `Ord` on `Route`)

## License

MIT OR Apache-2.0
