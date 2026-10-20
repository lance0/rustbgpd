# ADR-0141: Owner-scoped lease on controller-injected routes

**Status:** Accepted
**Date:** 2026-10-19

## Context

Routes and FlowSpec rules injected through `InjectionService` live until a
client deletes them or the daemon exits. If the controller that injected them
stops while the daemon stays up, nothing withdraws them. For a FlowSpec discard
rule that leaves a stale filter in place. For a remotely triggered blackhole
(RTBH) host route it keeps dropping all traffic to the victim indefinitely.
A FlowSpec/RTBH controller cannot safely drive detector-triggered blackholes
through the daemon until injected state can expire when its controller stops.

What exists today:

- `AddPath` builds a `Route` with the local sentinel peer `0.0.0.0`
  (`crates/api/src/injection_service.rs:41`, `:218-319`) and sends
  `RibUpdate::InjectRoute`; `DeletePath` sends `WithdrawInjected`
  (`:321-368`). `AddFlowSpec` and `DeleteFlowSpec` do the same with
  `InjectFlowSpec` / `WithdrawFlowSpec` (`:370-486`). Each handler awaits
  queue admission on the RIB channel and then the RIB actor's reply.
- The RIB stores local state in the Adj-RIB-In of `LOCAL_PEER`
  (`crates/rib/src/manager/helpers.rs:15`). Unicast is keyed by
  `(prefix, path_id)` (`crates/rib/src/manager/distribution/unicast.rs:1725-1787`),
  FlowSpec by `(afi, rule)` with `path_id` 0
  (`crates/rib/src/manager/distribution/flowspec.rs:126-201`). Neither key
  records which client created the entry, and `Route` has no owner field.
- `InjectionService` is constructed once per gRPC listener
  (`crates/api/src/server.rs:2179`, `:2461`), so per-service state is not
  daemon-wide.
- Every injection RPC is `operator_only` (`crates/api/src/authz.rs:740-775`).
  The authz layer forwards the resolved role, not the principal name, to the
  handler (`crates/api/src/authz_runtime/layer.rs:133`). `operator_only`
  calls are audited at `WARN` on every call
  ([ADR-0064 §7](0064-grpc-authorization.md#7-audit-logging),
  `crates/api/src/authz_runtime/decision.rs:128`).
- [ADR-0139](0139-flowspec-controller-contract.md) puts `AddFlowSpec`,
  `DeleteFlowSpec` and `ListFlowSpecRoutes` in the v1 inventory with explicit
  outcomes. `InjectionService`'s four unicast and FlowSpec methods are
  hashed in [the v1 inventory](../reference/v1-stable-surface.json).
  Unicast injection is separately gaining the same contract (next-hop-self,
  `allow_missing`, add outcome); this ADR builds on that change.
- The RIB already runs monotonic deadlines on `tokio::time::Instant`
  (`crates/rib/src/manager/graceful_restart.rs:31`), and has a test hook that
  stalls ingest (`crates/rib/src/manager/mod.rs:2715`).

## Decision

### 1. Model: one lease per owner, renewed by a cheap RPC

A route or rule may be added with an **owner** and a lease. The lease belongs
to the owner, not to the route: one deadline covers everything that owner
injected. A `RenewLease` RPC moves that one deadline. When it passes, the
daemon withdraws all of the owner's unicast routes and FlowSpec rules in one
batch.

The lease answers "is this controller alive?". Per-route lifetime is the
controller's own policy (its mitigation TTLs) and stays there.

Rejected:

- **Per-route lease renewed by re-adding.** N RPCs and N RIB turns per
  interval, a guaranteed no-churn `UNCHANGED` path on every one, and still no
  way to say "this controller is dead". Renewal would queue behind RIB work,
  so a loaded daemon would expire leases during the attack being mitigated.
- **Lease bound to an open heartbeat stream.** Exact, but a proxy idle
  timeout, a TLS credential reload or a brief API stall would withdraw every
  blackhole at once. Adding a grace period makes it a lease again, with a
  stream to keep healthy as well.
- **Owner tag without a lease.** Not offered. An owner always has a lease, so
  an owned route can never be permanent by accident. Unowned injection keeps
  today's behaviour.

### 2. Lease generation and the expired-renewal contract

The controller contract requires that a renewal report when the lease has
already expired, so that a renewal arriving just after expiry cannot look
successful while the routes are gone.

- Each owner's live lease has a **generation**,
  `LeaseGeneration { fixed64 incarnation; uint64 sequence; }`. The
  `incarnation` is a random 64-bit value drawn once per process start from the
  OS random source, through std's randomly keyed hasher, so no new dependency
  is needed. `sequence` comes from one daemon-wide counter that only
  increases. A renewal must match both fields. A generation from a previous
  process therefore cannot match a lease started after a restart, even when
  the new process's counter reaches the same `sequence`. No wall clock is
  involved.
- Only a leased add (section 3) can start a generation. The generation is
  returned by the add that starts it, by every leased add, by `RenewLease` and
  by the read RPC.
- `RenewLease(owner, generation, lease_seconds)` succeeds only if the
  generation is the owner's live lease. Otherwise it returns
  **`FAILED_PRECONDITION`** and changes nothing. This covers an unknown owner,
  an expired lease (reaped or not yet reaped) and a superseded generation.
  Renewal never creates or resurrects a lease.
- **Recovery:** after `FAILED_PRECONDITION`, or when a leased add returns a
  generation other than the one the controller holds, the controller must
  assume its previous state is gone and re-add its full desired state. The
  first leased add starts the new generation.

`FAILED_PRECONDITION` was chosen over an `OK` response with an `EXPIRED`
outcome. An `OK` reply that a client fails to inspect reads as success, which
is exactly the failure this contract exists to prevent. A non-`OK` status
cannot be ignored silently by generated clients. On this RPC
`FAILED_PRECONDITION` has one meaning, "that generation is not live";
malformed input is `INVALID_ARGUMENT`. Clients branch on the code, not on the
message text. The rejection makes no mutation.

**Liveness rule.** A lease is live at instant `t` if and only if
`t < deadline`, on `tokio::time::Instant`. Renewal, leased add and expiry all
evaluate it under the lease-table lock. A renewal at exactly the deadline
loses, whether or not the expiry tick has run yet.

### 3. Proto shape

Leased injection uses **new RPCs** that wrap the existing request messages.
It does not add a field to `AddPath` or `AddFlowSpec`, which keep their
current messages and behaviour.

```proto
message InjectionLease {
  // 1-64 bytes of [A-Za-z0-9._-]. Used verbatim as a metric label and log field.
  string owner = 1;
  // Required, 5..=3600. A leased add that starts the owner's lease sets its
  // deadline to now + lease_seconds. A leased add that joins a live lease
  // extends the deadline to max(current, now + lease_seconds) and never
  // shortens it; only RenewLease can shorten a lease.
  uint32 lease_seconds = 2;
}
message LeaseGeneration { fixed64 incarnation = 1; uint64 sequence = 2; }

rpc AddLeasedPath(AddLeasedPathRequest) returns (AddLeasedPathResponse);
message AddLeasedPathRequest { AddPathRequest path = 1; InjectionLease lease = 2; }
message AddLeasedPathResponse { AddPathResponse result = 1; LeaseGeneration generation = 2; }

rpc AddLeasedFlowSpec(AddLeasedFlowSpecRequest) returns (AddLeasedFlowSpecResponse);
message AddLeasedFlowSpecRequest { AddFlowSpecRequest rule = 1; InjectionLease lease = 2; }
message AddLeasedFlowSpecResponse { AddFlowSpecResponse result = 1; LeaseGeneration generation = 2; }

// DeletePathRequest / DeleteFlowSpecRequest gain:
//   string owner;          // must match the entry's owner ("" = unowned)
//   bool override_owner;   // delete regardless of owner

rpc RenewLease(RenewLeaseRequest) returns (RenewLeaseResponse);
// Sets the deadline to exactly now + lease_seconds, which may shorten it.
message RenewLeaseRequest { string owner = 1; LeaseGeneration generation = 2; uint32 lease_seconds = 3; }
message RenewLeaseResponse { LeaseGeneration generation = 1; uint32 lease_remaining_ms = 2; }

rpc ListInjectionLeases(ListInjectionLeasesRequest) returns (ListInjectionLeasesResponse);
// Optional owner filter; each row: owner, generation, lease_seconds, lease_remaining_ms.
```

A call to a leased RPC is a **leased add**. A leased add on an owner with a
live lease joins the lease and extends it to
`max(current deadline, now + lease_seconds)`: the add is itself proof that the
controller is alive. An add never shortens the lease. Otherwise one add with a
short `lease_seconds` would pull in the deadline for every route the owner
holds. Only `RenewLease` sets the deadline exactly, and it may shorten it,
because it is the one call whose purpose is to state the owner's whole
lease. A missing `lease` returns `INVALID_ARGUMENT`. Remaining
time is reported in milliseconds from the monotonic deadline, never as a
wall-clock timestamp.

**Why separate RPCs.** Proto3 servers ignore unknown fields. An older daemon
would accept a `lease` field on `AddPath`, install permanent state and
report success. Two alternatives were rejected:

- **A mandatory capability probe** before injection. The daemon can be
  downgraded and restarted between the probe and the add.
- **A rule that the client deletes whatever came back with generation 0.**
  That leaves permanent state if the client dies between the add and the
  delete.

An older daemon answers `UNIMPLEMENTED` to an unknown method and changes
nothing. So a leased add either creates leased state or creates no state, on
every server version, including across rollout and rollback. The controller
contract forbids retrying a failed leased add through `AddPath` or
`AddFlowSpec`.

**Read-back.** `Route` and `FlowSpecRouteEntry` rows sourced from `0.0.0.0`
gain `injection_owner`, `lease_generation` (a `LeaseGeneration`) and
`lease_remaining_ms`. These
are unset for unowned entries. A remaining time of 0 means "expired,
withdrawal pending".

**Outcomes and status codes** (adds and deletes keep their existing
outcomes):

| Case | Status |
|------|--------|
| `owner` malformed; `lease_seconds` 0, below 5 or above 3600 | `INVALID_ARGUMENT` |
| Leased add would create a 65th live owner | `RESOURCE_EXHAUSTED` |
| Leased add on a key held by another owner, or by no owner | `FAILED_PRECONDITION` |
| Unowned add on a key held by an owner | `FAILED_PRECONDITION` |
| Delete with an `owner` that does not match the entry, including `""` on an owned entry, without `override_owner` | `FAILED_PRECONDITION` |
| `RenewLease` of a generation that is not live | `FAILED_PRECONDITION` |

Every `FAILED_PRECONDITION` and `RESOURCE_EXHAUSTED` above leaves the RIB,
the lease table and the wire unchanged. Moving a key between owners takes a
delete followed by an add.

Converting an unleased entry to a leased one is also delete-then-add; a
leased add never adopts an unowned key. Adoption would let a controller
claim, and later expire, routes that an operator installed by hand. The cost
is that the key is withdrawn between the delete and the add. A controller
that cannot accept that gap should use a fresh key, such as another
`path_id`, and delete the unleased entry after the leased one is in place.

### 4. Where state lives

- **Lease table** (`owner → {generation, deadline, lease_seconds}` plus a
  pending-expiry queue of `(owner, generation, deadline)`). There is one daemon-wide instance behind a
  synchronous mutex, defined in `rustbgpd-rib` and shared by every
  `InjectionService` instance and the RIB manager. No lock is ever held
  across an `.await`. Every operation under it is O(1), or O(live owners)
  for the tick, with live owners capped at 64.
- **Ownership index**, inside the RIB actor: `local key → (owner, generation)`
  and `owner → keys`, for `LOCAL_PEER` entries only. It is kept beside
  `Route` and is not a field on `Route`, so received routes do not grow.
  It is authoritative for mismatch checks because it changes in the same turn
  as the Adj-RIB-In.

**Renewal never touches the RIB.** `RenewLease` and `ListInjectionLeases` are
served from the lease table in the handler. A stalled or backlogged RIB does
not delay renewal, so a loaded daemon does not expire leases during the
attack its blackholes are mitigating.

**Leased add** runs entirely in the RIB turn that commits it. The steps are:

1. Check the ownership index and reject a mismatch.
2. Take the table lock and join the live lease, or start a new generation.
   If the owner's previous lease is past its deadline but not yet reaped,
   first move it, with its deadline, to the pending-expiry queue.
3. Insert the route and tag it with the generation.

The liveness decision is taken at the commit instant, so there is no window
between "lease checked" and "route inserted". If the caller cancels, the RIB
still commits. That route is owned and expires with its lease, unlike today's
orphaned permanent route.

**Expiry** is driven by one task spawned with the RIB, holding a clone of the
RIB sender. It sleeps until the earliest deadline and is woken by a `Notify`
when the table changes. On waking, under the lock, it does two things. It
moves every owner whose deadline is `<= now` from the table to the
pending-expiry queue, so those generations are dead to renewals from that
instant. It then drains the queue. After releasing the lock, it sends one
`RibUpdate::ExpireInjectionLeases { leases: Vec<(owner, generation, deadline)> }`.
The deadline travels with the generation. Expiry has deleted the table
record, and the owner may already hold a newer generation with a different
deadline, so the RIB computes the deadline-to-apply lag reported in
section 10 from the message, never from a lookup at apply time. The RIB
withdraws every key of each owner whose tag is at or below the expired
generation; within one process the incarnation is fixed, so this compares
`sequence`. It
then runs one unicast `recompute_best` + `distribute_changes`, and one
`recompute_and_distribute_flowspec`, over the affected sets. Every generation
leaves the table exactly once, through this queue.

Edges:

- **Expiry vs re-add.** A re-add that commits after the generation died starts
  generation g+1 and retags the key. The later `Expire(g)` skips it because
  its tag is greater than g. An identical re-add reports `UNCHANGED` and
  causes no wire churn. If the expiry already ran, the re-add is `CREATED` and
  re-announces.
- **Expiry vs in-flight add.** The add's generation is decided at commit
  time. A queued add that commits after the deadline starts g+1. The
  response returns g+1, which tells the controller to resynchronise.
- **Expiry vs `DeletePath`/`DeleteFlowSpec`.** Both run in RIB turns, and
  whichever is first removes the key. Expiry skips missing keys. A later
  delete gets `NOT_FOUND`, or `NOT_PRESENT` with `allow_missing`. A delete
  does not renew.
- **Slow RIB.** The expiry send waits for queue admission without holding
  the table lock. Expired routes stay advertised until the RIB applies the
  batch, so the lag is the RIB queue latency. It is logged and is not hidden.
  Renewals and new generations proceed meanwhile.
- **Bounded work per tick.** The tick does O(live owners) table work and
  sends one message. The RIB applies it in one turn, the same way it applies
  a peer-down of the same size (`crates/rib/src/manager/peer_lifecycle.rs:121`).
  One owner holds at most 16,384 keys, unicast and FlowSpec together, so a
  batch for all 64 owners withdraws at most about one full table, the size
  of a full-table peer-down. A leased add of a new key past that cap returns
  `RESOURCE_EXHAUSTED` and changes nothing; keys awaiting expiry still count.
  If measurement shows that a batch this size stalls the actor, expiry
  adopts the peer-down chunking rather than adding a new mechanism.
- **Graceful Restart selection deferral** delays distribution of the expiry
  withdrawal exactly as it delays an injected add today.

### 5. Failure direction

Expiry **removes local intent**: the daemon withdraws the owner's entries
from the `0.0.0.0` Adj-RIB-In, and the normal selection and distribution
paths follow. It never installs anything. Whether traffic then flows depends
on what else the network holds. As in
[ADR-0139](0139-flowspec-controller-contract.md), the daemon does not
promise remote acceptance, forwarding or enforcement. The proto comments
state this per family:

- **Unicast:** the local route leaves selection. If it was selected, peers
  receive a withdrawal or the next-best path. A blackhole that only this
  controller originated stops attracting the victim's traffic to the discard
  next hop. An equal or better route from another source keeps applying.
- **FlowSpec:** the local rule is withdrawn. A received rule with the same
  key can already out-select the local one, and it then stays selected and
  advertised
  (`flowspec_injection_reports_local_outcomes_and_reconciles`,
  `crates/api/src/injection_service.rs:2682-2775`). In that case filtering
  continues after expiry. Expiry guarantees only that this owner's intent no
  longer contributes.

The lease bounds the lifetime of a dead *controller's* state. It does not
cover the daemon dying: then peers drop the routes when the session closes,
or after their Graceful Restart and Long-Lived Graceful Restart stale timers
if they are acting as helpers.

### 6. Clock

`tokio::time::Instant` throughout, with no wall clock in any deadline or
generation. Tests use `#[tokio::test(start_paused = true)]` and
`tokio::time::advance`.

### 7. Bounds

- `lease_seconds` is 5..=3600; 0 and out-of-range values are rejected. The
  floor stops a renewal interval shorter than one RIB turn under load. The
  ceiling keeps a forgotten controller's blast radius to about an hour.
- There are at most 64 live owners, and each holds at most 16,384 keys.
- These are constants, not config. A knob is added only when an operator
  needs a different value.

### 8. Authorization

- **`RenewLease` is `operator_only`,** the same tier as the adds. A generation
  is not a capability. The `automation` role reaches `sensitive_read` and
  `mutating` (`crates/api/src/authz.rs:48-55`), so at `mutating` an
  automation credential could list every owner and generation and keep a
  dead controller's blackholes alive indefinitely. Delaying a withdrawal has
  the same blast radius as the injection. `AddLeasedPath` and
  `AddLeasedFlowSpec` are `operator_only`. `ListInjectionLeases` is
  `sensitive_read`.
- **Audit volume.** ADR-0064 §7 logs every `operator_only` call at `WARN`
  (`crates/api/src/authz_runtime/decision.rs:128`). That would mean one WARN
  per controller every few seconds. This ADR amends §7 for exactly one
  method, using the shape the `read` tier already has, where `handler_ok`
  logs at `DEBUG` (`decision.rs:146`):
  - `RenewLease` with result `handler_ok` is logged at `INFO`;
  - every other `RenewLease` result is logged at `WARN`, as today. That
    covers authentication or role denial, `FAILED_PRECONDITION` and
    `INVALID_ARGUMENT`.

  Every call is still logged, with the same fields, and still counted in the
  authorization decision metric. No other method's level changes.
- **The owner is a label, not bound to a principal.** Handlers do not
  receive the principal today. A bearer-token listener has one principal for
  every client, and every principal that can add or renew already holds the
  operator role, which can also call `Shutdown`. Owner checks prevent one
  controller from changing another's state by mistake; they are not a
  security boundary between operators.
- **Owner in the audit line.** Leased adds, `RenewLease`, deletes and every
  `override_owner` use record the owner and the generation in the request
  summary (`GrpcAuditHandle::set_summary`, `crates/api/src/audit.rs:18`).
  The audit line already carries the caller's principal, role and listener.
  Each line therefore ties a principal to the owner it acted on, and an
  override names the owner it bypassed.
- **Admin override:** `override_owner` on `DeletePath` and `DeleteFlowSpec`
  (both `operator_only`) removes an owned entry without knowing its owner.
  `rbgp`'s delete commands expose it as `--override-owner`. There is no bulk
  "release owner" RPC: stopping the controller and waiting one lease does
  that.

### 9. SIGHUP, restart and shutdown

- **SIGHUP and config transactions** do not touch the lease table or
  injected routes; neither is config.
- **Restart** loses every route, rule and lease, as it does today. The
  controller's next `RenewLease` returns `FAILED_PRECONDITION`, which triggers
  the recovery in section 2. `GetHealth.uptime_seconds` resetting remains the
  restart signal for unowned injection.
- **Shutdown:** the expiry task holds a strong RIB sender. While that sender
  exists, the RIB's receive loop never sees `None`
  (`crates/rib/src/manager/mod.rs:6146-6162`). Shutdown therefore cancels
  the expiry task explicitly, through a cancellation signal that its `select!`
  observes both while sleeping and while waiting for RIB queue admission.
  Shutdown then joins the task before it waits for RIB termination. A
  cancelled expiry sends no withdrawal; sessions closing withdraw the routes
  at peers.
- **Expiry task failure:** if the task exits unexpectedly, leases stop
  expiring and owned state becomes permanent without anyone seeing it.
  `main` supervises the task beside the RIB handle (`src/main.rs:6445`), and
  an unexpected exit starts shutdown as a component failure.

### 10. Observability

- `bgp_injection_lease_expiries_total{owner}`, a counter, and
  `bgp_injection_leases`, a gauge of live owners. The `owner` label takes at
  most 64 distinct values per process; names after that are reported as
  `owner="_other"`, so series do not accumulate as owners churn.
- Log events:
  - `INFO` when a generation starts (owner, generation, lease_seconds);
  - `WARN` when one expires (owner, generation, unicast and FlowSpec counts
    withdrawn, lag from deadline to RIB apply in ms);
  - `DEBUG` when a renewal is rejected.
- **`rbgp`:** the existing local-route and FlowSpec reads show owner and
  remaining lease. No dedicated lease command; `ListInjectionLeases`, the
  metric and the log cover diagnosis. `rbgp`'s add commands take no lease
  flags, because a one-shot CLI cannot renew.

### 11. Compatibility

Additive. `AddPath` and `AddFlowSpec` are unchanged, and unowned entries
never expire. Leased injection exists only on the new RPCs, which an older
daemon rejects with `UNIMPLEMENTED` without creating state (section 3).
Rolling back to such a daemon restarts it, so every owned entry is dropped
as on any restart, and the controller's next renewal or leased add fails.
Owned entries are new, so rejecting an unowned delete of an owned entry breaks
no existing client. The new delete fields and RPCs change the
`InjectionService` signature and message-graph hashes in the v1 inventory.
That hash update lands in its own commit, and the surface enters the
inventory with its implementation and the interop evidence below.

### 12. Test plan

Unit, in `crates/api` and `crates/rib`. Each test must fail with its guard
removed.

- Validation: owner length 0/1/64/65 and illegal bytes; `lease_seconds`
  0/4/5/3600/3601; with each, the RIB and table are unchanged.
- Owner cap: the 65th owner gets `RESOURCE_EXHAUSTED` and no route is
  inserted. Key cap: an owner's 16,385th key gets `RESOURCE_EXHAUSTED`, while
  replacing a held key and other owners' adds still succeed.
- Mismatch matrix: owned onto another owner, owned onto unowned, unowned onto
  owned, delete with the wrong owner, delete with `""` on owned, and
  `override_owner` succeeding. Each rejection leaves the RIB, table and
  outbound unchanged.

Paused clock:

- Expiry withdraws both families in one RIB update, and the withdrawal reaches
  a peer's outbound.
- Renewal before the deadline prevents expiry.
- Adds never shorten a lease. With a live 60 s lease, a leased add with
  `lease_seconds = 5` leaves the deadline where it was. Advancing 10 s
  expires nothing. A leased add with a longer value extends the deadline. A
  `RenewLease` with `lease_seconds = 5` then sets the deadline to now + 5 s,
  and the lease expires on schedule.
- Delete-then-add conversion: a leased add on an unowned key returns
  `FAILED_PRECONDITION` and leaves the entry unowned. After a delete, the same
  leased add succeeds.
- Expiry lag across generations: let generation g expire and capture the
  expiry task's batch through a test seam on its RIB sender, so the batch is
  not yet delivered. A leased add then commits in the RIB and starts
  generation g+1, with a different deadline. Advance the clock and deliver
  the captured batch. The `WARN` line's lag field reports g's
  deadline-to-apply lag, not one computed from g+1's deadline, and the key
  tagged g+1 survives. A generation can start only in a RIB turn, so the
  test cannot stall the RIB and start g+1 at the same time.
- Unowned routes survive any advance.
- Race: a late renewal of generation g after a re-add started g+1 gets
  `FAILED_PRECONDITION` and leaves g+1's deadline unchanged.
- Race: expiry vs an in-flight add. Stall ingest with the existing hook, queue
  a leased add, advance past the deadline, release. The add returns g+1,
  `Expire(g)` withdraws only g-tagged keys, and a re-added old key survives
  with `UNCHANGED` and no outbound change.
- Race: renewal vs the tick. A renewal at `deadline - 1ns` is renewed and the
  tick expires nothing. A renewal at exactly `deadline` is rejected whether
  or not the tick has run.
- Race: expiry vs delete in both orders.
- With the RIB stalled, `RenewLease` completes within a bounded test timeout.
- Restart fencing: build a lease table, take a lease (incarnation A, sequence
  1), then build a second table standing in for the restarted process, with
  the counter starting from the same value and a different incarnation B.
  Re-add, which gives (B, 1), then renew with (A, 1): `FAILED_PRECONDITION`,
  and (B, 1)'s deadline is unchanged. A companion test builds two tables at
  the same paused-clock instant and asserts that their incarnations differ,
  proving the incarnation does not come from the clock.

Shutdown and supervision:

- Shutdown with no live leases: the expiry task, parked with no deadline,
  is cancelled and joined, and the RIB then terminates.
- Shutdown with the expiry send blocked: fill the RIB channel and stall
  ingest, let a lease expire so the task waits for queue admission, then shut
  down. The task is cancelled out of the send, joined, and the RIB
  terminates; nothing is withdrawn.
- An unexpected exit of the expiry task starts shutdown as a component
  failure.

Authorization and audit:

- `RenewLease`, `AddLeasedPath` and `AddLeasedFlowSpec` are `operator_only`
  in the method inventory, so an `automation` principal is denied.
- A successful `RenewLease` is audited at `INFO`. Denied and
  `FAILED_PRECONDITION` renewals are audited at `WARN`. Every other
  `operator_only` method still logs `handler_ok` at `WARN`.
- Leased adds, renewals, deletes and overrides carry the owner and
  generation in the audit summary.
- Against a server without the leased RPCs, a leased add returns
  `UNIMPLEMENTED` and creates no route.

Interop, beside the FlowSpec controller leg on FRR:

- A controller process adds an IPv4 /32 blackhole (`65535:666`) and an
  IPv4 FlowSpec discard rule with a 10 s lease, and renews every 3 s.
- Assert that FRR holds both across at least three lease periods.
- Kill the controller. Assert that FRR loses both within lease + 5 s, and not
  before the deadline.
- Restart the controller. Its renewal is rejected, it re-adds, and FRR
  regains both.

### 13. GoBGP API bridge

A bridge that translates a detector's GoBGP `AddPath` calls into injection
holds its own owner, for example `gobgp-bridge`, and renews while it runs.
This is a dead-man switch for the **bridge process**, not for the detector
behind it: a dead detector with a live bridge keeps its routes. A detector
that announces once and never re-announces loses its routes if the bridge is
down for longer than one lease, because the bridge has no desired state to
re-add. Both limits belong in the bridge's documentation.

## Consequences

- A FlowSpec/RTBH controller can bound how long its state outlives it.
  Detector-driven blackholes can rely on that bound.
- Two controllers sharing one daemon can tell their state apart and cannot
  overwrite each other's keys by accident.
- Controllers take on a renewal loop and must handle `FAILED_PRECONDITION`
  and generation changes by re-adding their full state.
- The daemon gains one small shared table, one task and one RIB message type.
  Renewal stays off the RIB actor.
- Expiry lag under RIB backlog is bounded by RIB queue latency, not by the
  lease. It is reported, not hidden.
