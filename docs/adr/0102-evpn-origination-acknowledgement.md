# ADR-0102: EVPN origination acknowledgement-awareness (Type 1/2/4)

**Status:** Accepted
**Date:** 2026-07-09

## Context

Three daemon-side actors originate EVPN routes into the RIB over the
`RibUpdate` mpsc channel, each command carrying a reply oneshot the RIB
answers after applying the operation (`handle_inject_evpn` /
`handle_withdraw_evpn`, `crates/rib/src/manager/distribution/evpn.rs`):

- the **local Type 2 MAC / MAC+IP originator**
  (`src/evpn_originator/`), driven by kernel FDB/neighbor observations
  through the `LocalMacOriginator` / `LocalMacIpOriginator` state
  machines;
- the **Ethernet Segment orchestrator** (`src/evpn_segment.rs`),
  publishing Type 4 ES, Type 1 EAD-per-ES, and Type 1 EAD-per-EVI
  routes;
- the **IP-VRF Type 5 originator** (`src/evpn_l3_originator.rs`).

The Type 5 originator was already acknowledgement-aware: its
`inject_one` / `withdraw_one` return `true` only on an acked `Ok(())`,
callers gate their `originated` map on that return value, and the
level-triggered reconcile pass retries anything still divergent.

The Type 1/2/4 paths were not. They awaited the reply oneshot but only
**logged** failures — a RIB rejection, a dropped reply, or a wedged RIB
left the originator believing it had published (or withdrawn) state the
RIB never applied. The asymmetry matters because the Type 2 state
machines commit their state (mobility-sequence ratchet,
`originated_key`) at *action-generation* time, necessarily — the
ratchet must advance atomically with the decision — so a lost operation
silently diverged the machine from the RIB with no reconcile pass to
repair it: the periodic RIB repoll projects *remote* (non-self-NH)
routes for contention tracking, not our own originations. The same
fire-and-log shape applied to the ES orchestrator's Type 1/4
publication, including teardown withdraws, whose loss strands routes in
peers' RIBs. Additionally, the MAC+IP path's `pending_ip_bindings`
buffer (ARP/ND observations racing ahead of AF_BRIDGE FDB) grew without
bound if the bridge never learned the MAC.

The Type 5 pattern cannot be copied verbatim: Type 5 *desired state* is
fully re-derivable on every pass from watch-channel snapshots, so
"don't advance `have` until acked" suffices. Type 2/1/4 intent lives in
state machines that advance when they emit actions. The
acknowledgement gate therefore has to sit **between** the machines and
the RIB, tracking emitted-but-unacknowledged operations explicitly.

## Decisions

1. **Three-tier model: desired / pending / confirmed.**
   *Desired* remains what it already was — the state machines' view,
   derived from kernel/config observation. *Pending* is a new
   per-actor tracker (`PendingRibOps`, `src/evpn_ack.rs`): every
   inject/withdraw sent to the RIB is registered under
   `(route identity = EvpnRouteKey, generation)` before its first
   attempt. *Confirmed* is reached only when the RIB's reply oneshot
   acknowledges the operation; only then does the success bookkeeping
   run (origination metrics, `OriginatedLocalMacCounts`).

2. **Timeouts and dropped replies keep the operation pending; a retry
   arm re-drives it with bounded backoff.** Each attempt awaits the
   reply for at most 5 s (`RIB_ACK_TIMEOUT`; the RIB replies inline
   while processing, so the timeout only trips when the RIB is wedged
   or severely backlogged). On any failure — closed channel, dropped
   reply, timeout, or active rejection — the operation stays pending
   and its next attempt is scheduled at `1s · 2^(attempts−1)` capped
   at **30 s** (`RETRY_BACKOFF_BASE` / `RETRY_BACKOFF_MAX`). Retries
   never give up: a withdraw must not be forgotten until acknowledged,
   and the cap bounds the cost of a persistent failure to one attempt
   per 30 s per route. Both actors gained a `select!` arm that sleeps
   until the tracker's earliest deadline and parks forever when
   nothing is pending.

3. **Supersession by route identity; stale acks dropped by
   generation.** The tracker holds at most one pending operation per
   `EvpnRouteKey`; submitting a new one replaces the old under a fresh
   generation. `confirm`/`defer`/`forget` are generation-checked, so
   an acknowledgement for a superseded operation can never clear (or
   re-schedule) its successor. Because every state transition already
   flows through the state machines — lifecycle drains emit withdraws
   for exactly the keys the machines believe outstanding, including
   unacknowledged injects — VNI removal/redefine, ESI drain, and
   segment teardown supersede stale pending work for free.

4. **Retries rebuild from the current model; unbuildable injects are
   dropped, withdraws never are.** An inject retry re-derives its
   route from the *current* instance/segment tables (Type 2:
   `build_originated_route` from the live `EvpnInstance` +
   `vni_to_esi`; Type 1/4: `build_es_route` from the live
   `SegmentState` + instance). If the VNI/segment left the model — or
   a Type 2 key's RD no longer matches its instance — the pending
   inject is dropped (`forget`): the model change that removed it
   already superseded the route's state with withdraws. Withdraw
   retries need only the key and always proceed. A withdraw rejected
   with `NotFound` is treated as **confirmed**: absence is the
   withdraw's goal (the typical cause is a paired inject that was
   itself lost), and retrying it forever would be a livelock against a
   route that will never exist.

5. **Correctness leans on three existing properties, now
   load-bearing.** (a) RIB inject/withdraw are idempotent per key —
   `insert_evpn` is last-write-wins, withdraw of an absent key is a
   reported no-op — so retrying an operation whose earlier attempt
   actually applied (e.g. an ack lost after apply) is harmless.
   (b) The RIB command channel is FIFO, so a superseding operation
   sent after a possibly-applied predecessor lands after it and the
   final RIB state matches the final intent. (c) Origination is
   single-writer per route identity within each actor. No RIB-side
   changes were needed: the reply oneshot is created per attempt by
   the originator, so the reply is already correlated to
   `(key, generation)` at the await site — no identity echo required
   in the protocol.

6. **Nothing is persisted; restart rebuilds intent from observation
   and reconciles idempotently.** The trackers are in-memory only. On
   restart the kernel dump replays FDB/neighbor state into fresh state
   machines and config replays segment definitions; origination then
   re-injects idempotently against whatever the (also restarted) RIB
   holds. Persisting pending operations would add a second source of
   truth that can contradict observation — the class of bug this ADR
   removes. This also settles **MAC-mobility ratchet safe-forget**:
   `our_seq` is deliberately not persisted; after a restart the first
   contended learn re-derives it as `remote_seq + 1` from the live
   remote view, which is exactly RFC 7432 §15.1's recovery behavior.

7. **The unmatched pending-IP-binding buffer is bounded.**
   `pending_ip_bindings` exists only to absorb AF_INET/AF_INET6 NEIGH
   events racing ahead of AF_BRIDGE FDB — a reorder buffer, not a
   database. It is now capped at **4096 `(VNI, MAC)` entries** and
   **16 IPs per MAC** (`MAX_PENDING_IP_BINDING_MACS` /
   `MAX_PENDING_IPS_PER_MAC`, `src/evpn_originator/observation.rs`).
   Overflow drops the new binding with a warning rather than evicting
   an old one (eviction just moves the loss); a dropped binding
   self-heals on the next kernel neighbor event for the pair once the
   MAC has surfaced. The caps comfortably exceed default kernel
   neighbor-table sizes (`gc_thresh3` = 1024).

## Consequences

- A dropped reply, RIB backpressure, or a transient wedge can no
  longer permanently lose a Type 1/2/4 origination or withdrawal; the
  worst case is delayed convergence at the backoff cadence, visible as
  `evpn_local_origination_errors_total` increments plus per-attempt
  warnings.
- Type 2 withdraw semantics changed slightly: a `NotFound` rejection
  now also runs `OriginatedLocalMacCounts::record_withdraw`, keeping
  the operator-facing per-VNI MAC counts honest when the paired inject
  was lost (previously the count could strand).
- A persistently rejecting RIB retries forever at 30 s intervals per
  route. Acceptable: today's RIB never rejects injects and rejects
  withdraws only with `NotFound` (which confirms), so this arm is
  future-proofing, and the log/metric trail makes it diagnosable.
- The actors do one extra map insert/remove per operation and hold a
  clone of each in-flight action — noise next to route construction.
- Scope: SVI publication keeps its existing shape; it is
  config-derived, re-published on reconfiguration, and was not part
  of the observed loss class. Extending the tracker to it is
  mechanical if evidence appears. Type 3 (IMET) routes its
  inject/withdraw through the bounded `send_and_ack` wait — its
  converge callers hold the IMET controller mutex across the ack
  await, so an unbounded wait on a wedged RIB would lock every later
  EVPN runtime converge out — but keeps its own outcome mapping (an
  ack timeout reports `RibUnavailable`) rather than adopting the
  pending-op tracker.
