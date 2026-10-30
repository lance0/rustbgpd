# ADR-0144: Guarded FlowSpec mutation contract

**Status:** Accepted; the RIB enforcement, the RPCs and the qualification land
as separate changes.
**Date:** 2026-10-30

## Context

[ADR-0141](0141-injection-owner-lease.md) gives injected routes and FlowSpec
rules an owner and a lease, so a controller's state expires when the
controller stops renewing it. [ADR-0143](0143-flowspec-direct-ip-actions.md)
adds the direct target-IP action that a scrubber-diversion controller needs,
and states that it adds neither bounded authorization nor per-admission
revisions. A controller that diverts live traffic needs both, because three
gaps remain in the leased contract:

- **An admitted mutation can commit arbitrarily late.** A request can wait
  before its handler runs, wait for RIB queue admission, and wait behind RIB
  backlog. A client timeout cancels none of these. The lease does not fence
  a late mutation: a delayed leased add whose owner's lease already expired
  starts a fresh generation, and a delayed `RenewLease` sets the deadline to
  its arrival time plus `lease_seconds`. Either can bring back a diversion
  the controller had already given up on.
- **A late delete cannot tell admissions apart.** The lease generation
  belongs to the owner and is shared by every key the owner holds, so it does
  not change when one key is deleted and added again. A delete delayed past a
  newer add of the same key by the same owner removes the newer admission.
- **Existing methods would bypass a new fence.** If the fence were a check on
  each guarded key, a legacy leased add of a new key under the same owner name
  would still join that owner's lease and extend it with no fence at all.

This ADR records the contract that closes these gaps for FlowSpec. It extends
ADR-0141; everything not stated here keeps ADR-0141's behaviour.

## Decision

### 1. New guarded RPCs

Four new methods in `InjectionService`, named "Guarded" because the existing
methods stay as they are rather than being replaced:

- `IssueMutationWindow`: issue a mutation window to an owner.
- `AddGuardedFlowSpec`: a leased FlowSpec add checked against a window and
  carrying an admission revision. Its request wraps `AddFlowSpecRequest`.
- `DeleteGuardedFlowSpec`: an owner-scoped delete fenced by the admission
  revision.
- `RenewGuardedLease`: a lease renewal checked against a window.

Existing methods gain no optional fields. Proto3 servers drop unknown fields,
so an older daemon would commit the mutation without the fence. An older
daemon answers an unknown method with `UNIMPLEMENTED` and changes nothing; a
credential without the operator role gets `PERMISSION_DENIED` instead. A
controller therefore treats any non-`OK` reply as a refusal, and must not
retry a refused guarded mutation through the legacy methods.

All four methods are `operator_only`, the tier of every injection mutation
(ADR-0141 §8). Successful `RenewGuardedLease` and `IssueMutationWindow` calls
are audited at `INFO`, extending ADR-0141's exception for `RenewLease`;
otherwise a controller would log a `WARN` every few seconds. Every other
result of those two methods, and every call to the other two, keeps the
`WARN` level.

These methods start outside the v1 contract: they are listed as explicitly
outside v1, their read-back fields join the unstable or excluded field lists,
and the stable digests do not change.

### 2. Server-issued mutation window

The daemon issues a **mutation window** to an owner: an identifier, made of
the process incarnation and a sequence number, and an expiry on the monotonic
clock. The lease table stores each window as
`sequence → (incarnation, owner, expiry)`. A window may be used by any number
of guarded adds and renewals of its owner until it expires.

The window is checked **at the commit instant**, inside the lease-table
operations that ADR-0141 already runs at commit: the leased admission that
runs in the RIB turn which inserts the rule, and the renewal served from the
table. Both read the clock after taking the table lock, and the admission has
no `.await` between the check and the insert. A window that is unknown,
expired, issued to another owner, or issued by another process is refused
with `FAILED_PRECONDITION` and reason `WINDOW_NOT_LIVE`, and nothing changes.
Because the check runs at commit, it covers delay before the handler, the
wait for queue admission and RIB backlog alike.

The window also **caps the lease deadline**:

- A guarded add, including an unchanged re-add, sets the owner's deadline to
  `min(max(current, now + lease_seconds), window expiry)`. For an owner with
  no live lease, `current` is absent and the deadline is
  `min(now + lease_seconds, window expiry)`.
- A guarded renewal sets it to `min(now + lease_seconds, window expiry)`.

A guarded owner's lease therefore never outlives the latest window it used.
Unlike a legacy leased add, a guarded add can shorten the deadline, but only
down to the window's expiry.

**Limits.** These are constants, not configuration, as in ADR-0141 §7:

- A window lives at most **H = 120 s**.
- An owner holds at most **64 live windows**.
- The table holds at most 64 × 64 = 4,096 live windows in total, the
  per-owner cap times ADR-0141's live-owner cap, so window state stays bounded
  however many owner names are used.

A window request past either cap is refused with `RESOURCE_EXHAUSTED`, and
nothing changes. Expired windows do not count. A controller that hits the cap
must stop and report it, not fall back to the legacy methods.

When a controller stops, it stops issuing windows. Its lease then ends no
later than H after its last window was issued, and its rules leave the local
RIB once the expiry batch is applied (ADR-0141 "Slow RIB").

Rejected:

- **A client wall-clock deadline in the request.** It depends on clock skew
  between controller and daemon.
- **A deadline relative to receipt.** It misses the delay before the
  handler runs.
- **The lease alone.** A delayed first add starts a fresh generation, and a
  delayed renewal resets the deadline to its arrival plus `lease_seconds`.

### 3. Admission revision

Every guarded add carries a **revision**: a client-chosen, nonzero `u64`
stored with the key's owner and generation in the RIB's ownership index, and
reported by read-back beside them.

The client chooses it because a retry after an unknown outcome must carry the
same revision before the client could have learned a server-assigned one. The
lease generation cannot serve, because it is shared by sibling keys and does
not change when one key is added again.

**Add.** For a key the owner already holds:

- a different revision is refused with `FAILED_PRECONDITION` and reason
  `REVISION_MISMATCH`;
- the same revision with a different payload is refused the same way;
- the same revision with the same payload is `UNCHANGED`, and the window check
  and deadline cap still apply.

Every refusal leaves the RIB, the lease table and the wire unchanged. To
change a guarded rule, the controller deletes it with the old revision and adds
it with a new one. Ownership checks run first, so a key held by another owner
or by no owner is refused with ADR-0141's `OWNER_MISMATCH` or `KEY_UNOWNED`.

**Delete.** `DeleteGuardedFlowSpec` names the owner, the key and the revision:

| Case | Result |
|------|--------|
| Key absent | `NOT_PRESENT`; deleting again is idempotent |
| Key held by this owner at this revision | `DELETED` |
| Another revision, another owner or no owner | `FAILED_PRECONDITION`; nothing changes |

A delete needs no window. A late delete can only remove the admission it
names, and removal is the direction that fails safe.

The fence depends on the client: it must not reuse a revision for a different
admission of the same key. A counter that only increases is enough.

### 4. Separate owner namespace

Guarded methods store their owner under an internal prefix built from a
character that owner validation rejects (owners are 1-64 bytes of
`[A-Za-z0-9._-]`). The legacy leased add, `RenewLease` and the owner-scoped
delete validate the owner name, so they cannot name a guarded owner, and the
existing ownership comparison refuses them with `OWNER_MISMATCH` or a
generation that is not live. A legacy leased add of a new key under the bare
owner name starts or joins a separate legacy lease and cannot extend the
guarded one. Unowned adds and deletes of a guarded key are refused as for any
owned key.

The namespace needs no configuration, holds across restarts, and keeps the
expiry metric's owner labels distinct. A per-key refusal alone was rejected:
it leaves the lease joinable by a legacy add of a new key.

`override_owner` remains the operator's break-glass. It only withdraws, it is
not fenced by a revision, and it is audited with the owner it bypassed
(ADR-0141 §8).

### 5. Scope

FlowSpec only. Unicast and RTBH injection keep the ADR-0141 contract.

### 6. Clock

Windows and deadlines use `tokio::time::Instant`, as in ADR-0141 §6. That
clock is `CLOCK_MONOTONIC` on Linux, which does not advance while the host is
suspended, so a window's real-time bound does not hold across a host or VM
suspend. The daemon makes no claim across a suspend.

### 7. Promotion

A later change may promote the RPC shapes into the v1 contract, separately
from forwarding qualification. That promotion pins the API shape only, as
[ADR-0139](0139-flowspec-controller-contract.md) did for the FlowSpec
controller surface.

## Deferred

- Windows bound to a lease generation.
- A window-invalidation RPC.
- Per-key tombstones.
- Windows on deletes.
- Guarded unicast and RTBH injection.

## Residual risks

- **The router accepts the rule but does not forward.** Forwarding is a
  property of the receiving router and its software, not of this daemon, as
  in ADR-0139 and ADR-0143. Only a packet-level receipt from the router and
  scrubber qualifies it.
- **The daemon crashes and a peer keeps the rule.** The lease does not cover
  the daemon dying (ADR-0141 §5). A peer that negotiated Graceful Restart or
  Long-Lived Graceful Restart for FlowSpec can keep the diversion after the
  session drops, until its stale timers run out. A deployment either disables
  them for FlowSpec on diversion sessions or qualifies a daemon kill with
  them negotiated.
- **A stalled RIB delays removal.** Local removal takes at most the window
  lifetime plus the expiry apply lag, and that lag has no bound while the RIB
  is stalled (ADR-0141 "Slow RIB").
- **A client reuses a revision.** That defeats the delete fence (section 3).

## Consequences

- A guarded diversion cannot outlive its controller's last window by more than
  H plus the expiry apply lag, whatever the request delay.
- A late add, renewal or delete cannot revive an expired window or remove a
  newer admission of the same key.
- Legacy methods keep their behaviour and cannot reach guarded state.
- Controllers take on window issue, revision bookkeeping and the rule that a
  refused guarded mutation is never retried through a legacy method.
- The lease table gains one bounded window map; the RIB's ownership index
  gains one revision per key.
