# ADR-0127: Persisted Runtime-Config Settlement Watchdog

**Status:** Proposed
**Date:** 2026-08-11

## Context

[ADR-0076](0076-config-transaction-model.md) makes a config transaction one
daemon-wide operation under the shared runtime-config coordinator.
[ADR-0080](0080-cancellation-shielded-runtime-applies.md) shields multi-step
mutation from caller cancellation by moving it to a daemon-owned task. The
streamed apply path also hands its sole admission permit and candidate to that
detached operation. An RPC deadline or disconnect can end the response wait but
intentionally cannot cancel the apply or release admission.

That cancellation safety creates a liveness obligation shared by every
persisted runtime-config owner. After acquiring the coordinator, an executor
can await an actor reply, persistence reply, rollback reply, or reload bridge
adoption without a terminal bound. A lost reply can therefore retain the
coordinator (and, for streamed apply, its admission permit) indefinitely.
Later persisted mutations remain fenced until daemon restart, but the daemon
can continue to report process health even though its config plane cannot
settle.

PR #1607 and current source give unary and streamed `ApplyConfigTransaction`
ten minutes to acquire the coordinator. Expiry rejects only those waiting Apply
operations without mutation, while this ADR covers liveness after ownership.
That precursor does not bound rollback, confirm, abort, gNMI, or auto-revert
before ownership and does not close the underlying settlement-liveness issue.

This ADR defines the post-ownership contract. Transaction-watchdog substrate
exists in current source, but Proposed status does not claim the complete owner
roster, SIGHUP settlement/shutdown rules, or required recovery proof has
shipped.

### Implementation status (2026-08-12)

The shared watchdog, readiness/admission fence, Linux exit-70 terminal action,
and typed settlement wiring have shipped for transaction/Apply owners,
Neighbor4, FIB2, PeerGroup4, and Policy12. That is a partial roster, not
acceptance of this ADR or closure of the underlying issue.

SIGHUP ownership remains incomplete. The bounded metrics/log observability
described below and the final cross-roster recovery proofs also remain
incomplete. Until those land, this ADR stays Proposed and the source inventory
must distinguish shipped owners from the decision's full target roster.

## Decision

### One operation, one owner, one candidate

Every persisted runtime-config mutation has exactly one daemon-owned internal
operation record and one owner of the shared runtime-config coordinator. A
streamed transaction apply also has exactly one materialized candidate, one
consumed candidate token, and one held stream-admission permit. The transport
transfers the candidate and permit to the daemon-owned operation; it never
retains a second candidate, starts a replacement operation, or reacquires
admission for the same request.

The exact persisted coordinator-owner roster is:

- transaction owners: unary/streamed `ApplyConfigTransaction`,
  `RollbackConfigTransaction`, `ConfirmConfigTransaction`,
  `AbortConfigTransaction`, timeout auto-revert, and gNMI Set ordinary,
  `Commit`, `Confirm`, `Cancel`, and `SetRollbackDuration` operations;
- SIGHUP reload;
- Neighbor4: static and dynamic Add/Delete;
- FIB `SetFibTable` and `DeleteFibTable`;
- PeerGroup4: group Set/Delete and neighbor membership Set/Clear;
- Policy12: policy and neighbor-set Set/Delete, global import/export chain
  Set/Clear, and neighbor import/export chain Set/Clear.

Read-only Plan, Status, History, Get, and List operations, including
`ListFibTables`, are outside the watchdog. The shutdown/warm-checkpoint
coordinator acquisition is a fence, not a persisted mutation owner. A
source-closed inventory checker must keep this roster complete as entry paths
change.

`waiting-for-ownership` is a pre-watchdog state: the request is validated, but
has no coordinator guard or mutation authority. Ownership arms the watchdog
and begins exactly three live phases that advance monotonically:

1. `owned-preflight`: re-plan, token comparison, mutation-family validation,
   and other side-effect-free checks;
2. `mutating`: the first reversible runtime or journal mutation has begun; and
3. `settling/rollback`: persistence, finalization, confirmation-state
   publication, or compensating rollback is in progress.

Any owned live phase terminates through exactly one mutually exclusive branch:

- `clean_settled`: a typed terminal outcome proves success, a no-side-effect
  rejection, a fully acknowledged rollback, or an acknowledged SIGHUP
  known-partial result after the runtime snapshot and config bridge adopted
  the same authority; or
- `ambiguous_fenced`: ambiguity branches from any owned phase when settlement
  cannot be proved; no success or rollback claim is permitted and fail-stop is
  in progress.

Only `clean_settled` releases the coordinator and streamed admission normally.
`ambiguous_fenced` retains their logical ownership until process death. At
fail-stop or shutdown, every operation still queued in `waiting-for-ownership`
is rejected and no queued waiter may acquire the newly freed physical mutex.
A new process reconstructs authority from durable state.

The ten-minute precursor applies only to unary and streamed Apply operations in
`waiting-for-ownership`. It must not arm, reset, or consume the post-ownership
budget. Acquiring the coordinator changes the phase to `owned-preflight` and
arms the watchdog before any further await or side effect.

### Independent terminal watchdog

The 30-minute budget, five-second grace, and exit status 70 are implemented for
the shipped partial roster, but remain Proposed as complete-roster acceptance
criteria. Existing watchdog code does not by itself satisfy this amended
contract or its gates.

An owned operation gets one fixed, non-resettable 30-minute monotonic
settlement budget. This is the latest normal settlement deadline; independently
detected executor loss can advance fail-stop as specified below without
resetting or extending the budget. It is a fixed implementation contract, not
an operator config knob. The sealed
[IRR transactional-apply receipt](../perf/irr-transactional-apply-2026-08.md)
measured a 295.6 MB candidate with end-to-end completion no higher than 208.55
seconds and auto-revert no slower than 69.5 seconds. Thirty minutes is a
receipt-based conservative design target, not a normal-latency promise; family
limits stay separate. A streamed request that consumes every sequential bound
could take about 70 minutes and 5 seconds: 30 minutes of ingress, 10 minutes
waiting for ownership, 30 minutes owned, and 5 seconds of fail-stop grace.

One process-wide Linux OS thread owns all terminal clocks. After the grace
below it invokes audited `libc::_exit(70)`, a no-handler process primitive.
This is a deliberate Linux implementation contract, not a portable-standard
claim, and requires owner acceptance with this ADR. Before that call, the
user-space terminal wrapper performs no allocation, lock acquisition, tracing,
filesystem I/O, async work, handler dispatch, or unwinding; kernel descriptor
and process teardown can still occur and are outside that guarantee. A
multithreaded subprocess test must prove every thread dies and the parent
observes exact status 70. The operation can update an atomic phase and disarm
its registration only with a proved terminal `clean_settled` transition; it
cannot
extend or replace the deadline.

At 30 minutes without `clean_settled`, one atomic compare-and-swap irreversibly
wins the `owned -> ambiguous_fenced` race against settlement. It marks readiness
unavailable, closes admission for new persisted mutations, and requests
supervised shutdown. Settlement may disarm only if its compare-and-swap wins
first; after expiry wins, no late reply can reverse the fence or claim success.
The five-second grace exists solely to propagate that fence and emit one
bounded emergency diagnostic. It is not a rollback window, graceful actor
drain, telemetry-scrape interval, or permission to wait on the wedged operation.
If the process remains alive, the OS thread exits it at 30 minutes 5 seconds.

### Response and ownership are separate clocks

The RPC response deadline remains a transport concern. Deadline expiry,
disconnect, dropped response receiver, or caller cancellation may prevent a
client from learning the outcome, but never aborts the transaction task,
releases the coordinator, releases streamed admission, or disarms the terminal
watchdog. The daemon-owned operation continues toward `clean_settled` or
fail-stop.

The response therefore remains at-least-once ambiguous to the caller. Existing
transaction status is authoritative only for the confirmed-transaction
lifecycle it already reports. An ordinary Apply caller recovers by issuing a
fresh Plan and comparing effective config and its fresh token; there is no
ordinary-operation status record. This ADR adds no protobuf field, RPC, status
enum, or token format.

Awaiting or dropping a caller-side `JoinHandle` never cancels the detached task;
a dropped handle detaches, and the operation remains owned/running. Executor
`JoinError`, owner-guard drop, panic, unwind, or task abort after coordinator
acquisition advances the hard-exit deadline to five seconds after the loss.
The same exact compare-and-swap decides executor-loss versus a concurrent
`clean_settled` transition: loss cannot fence a prior settlement, and
settlement cannot revoke a loss-won fence. Unless already `clean_settled`, the
owner guard marks `ambiguous_fenced` before its coordinator guard or stream
permit can drop; the OS-thread registration outlives the task. Process abort
already meets fail-stop.

### Persistence and confirmed transactions

The watchdog covers ordinary applies, confirmed applies, confirm/abort work,
timeout auto-revert, and the gNMI adapter when they mutate under the same
coordinator. The phase record identifies these operation kinds without
creating a second commit model.

For an unconfirmed apply:

- Before atomic persistence publishes the candidate, restart uses the prior
  on-disk config as authority.
- After atomic persistence publishes it, restart uses the candidate on disk as
  authority even if the response or in-process finalization was lost.
- If publication cannot be proven at watchdog expiry, the running process says
  only `ambiguous_fenced`. Startup validates the one atomically published
  config object and fails closed under the existing persistence contract.

V3 authority has three explicit publication windows. Before locator
publication, no v3 boot authority exists and confirmed mutation must not begin.
After locator rename and directory fsync, the config-adjacent locator is the
sole pending boot authority and names fixed owner-private metadata and raw
normalized-prior objects. If locator publication acknowledgement is ambiguous,
the operation treats the locator as potentially authoritative, fences, and
lets boot inspection decide; it never cleans up speculatively.

For confirmed Apply the operation settles after that authority protects the
commit and the pending lifecycle is installed. For confirm, successful abort,
or auto-revert, durable locator unlink plus directory fsync is the terminal
point and disarms the watchdog before warning-only metadata/raw cleanup. That
cleanup cannot retain the coordinator or trigger fail-stop if it stalls.
Locator unlink or directory-fsync failure remains nonterminal, retains the
fence and authority, and proceeds to watchdog fail-stop if it cannot settle.
Restart with a retained locator performs the existing verified boot revert.

The typed terminal classifier is uniform across owner families.
`clean_settled` includes success, a proved no-side-effect rejection, a fully
acknowledged rollback, and the acknowledged SIGHUP known-partial case above.
`ambiguous_fenced` includes an accepted-command deadline, lost mutation or
persistence acknowledgement, failed or unacknowledged rollback, uncertain
publication, executor loss, and true SIGHUP reconcile or bridge ambiguity.
Pre-persistence, post-persistence, rollback, and lost-ack windows obey the same
rule: no success or clean-failure claim without proof. A family-local timeout
may advance an ambiguous operation to `ambiguous_fenced`; it never releases
ownership or proves settlement. The watchdog does not guess which side effect
completed. It fences, exits, and lets established durable authority decide
startup behavior.

### Fencing, observability, and shutdown

The internal operation record carries only bounded safe metadata for daemon
logs, metrics, and diagnostics:

- a daemon-generated operation ID;
- operation kind and current phase;
- monotonic elapsed time and configured watchdog budget;
- whether the response waiter is still attached; and
- terminal outcome or fail-stop reason.

Logs must carry the operation ID, phase, and elapsed duration. Metrics expose
the current phase and elapsed duration plus one counter for watchdog fail-stop,
but never use the operation ID as a label. Neither surface may include
candidate TOML, optimistic-concurrency or candidate tokens, confirm IDs,
comments, credentials, filesystem paths, digests, derived candidate fragments,
or free-form actor/error strings. Metric labels come from a closed enum.

The existing process availability gate is the first fencing mechanism at
watchdog expiry: readiness turns red and every entry point for a new persisted
mutation rejects work. An actor dequeue fence is additionally required only
where source inventory proves a producer can bypass the coordinator. A
closeable coordinator is sufficient for queued and future producers only when
an inventory and checker prove that every persisted producer passes through it.
No fence may reject settlement commands from the current owner. None of these
steps permits release of its coordinator or streamed admission before death.

Ordinary coordinated shutdown first closes mutation admission. A SIGHUP
rejected before ownership is a clean no-side-effect rejection. Once SIGHUP owns
the coordinator, shutdown must not abort its task: it waits for settlement or
the already-armed watchdog, then retains the coordinator as the
shutdown/warm-checkpoint fence. The same rule applies to every owned operation.
Shutdown cannot abort its `JoinHandle`, reset the deadline, start a parallel
rollback, or tear down a required actor while the operation is still trying to
settle. Watchdog expiry during shutdown follows the same readiness, fence, and
nonzero fail-stop path; it is not converted to a successful shutdown. All
queued coordinator waiters are rejected before teardown and cannot begin after
the owner settles or dies.

### Required proof before acceptance

Implementation is not complete until deterministic tests cover the phase and
recovery contract:

1. An injected deterministic watchdog driver holds each actor and persistence
   reply used by every persisted owner family. At 29 minutes 59 seconds the
   owner, coordinator, admission, and watchdog remain live; at 30 minutes the
   state becomes `ambiguous_fenced` exactly once. Tokio paused time cannot
   drive an OS-thread condition variable, so real OS-thread and subprocess
   tests must separately prove wake-up and terminal behavior.
2. Caller-`JoinHandle` wait/drop tests prove the operation remains owned/running.
   Executor `JoinError`, panic/unwind/task-abort, and owner-guard-drop tests prove
   immediate fencing before coordinator/permit release, OS thread still armed,
   and no new admission.
3. Adversarial tests stall owned preflight, first mutation, persistence before
   and after atomic publication, finalization, rollback, confirm, abort,
   auto-revert, and SIGHUP reconcile/bridge adoption. Each produces either a
   proved `clean_settled` result or the same fail-stop transition.
4. Real-binary subprocess tests prove readiness goes red, queued/new mutations
   reject, exit 70 occurs by the grace, and no second transaction begins.
5. Restart/fault tests cover unconfirmed persistence; v3 before, after, and
   ambiguous locator publication; confirmed Apply/confirm/abort/auto-revert;
   nonterminal locator unlink/fsync failure; and stalled post-terminal cleanup.
   They assert config and authority state, watchdog disarm, and lock release.
6. Fault injection must prove the watchdog still exits when the Tokio runtime,
   transaction task, relevant actor mailbox, persistence acknowledgement, and
   graceful-shutdown path are independently stalled.

The test matrix must exercise every roster family with a finite pairwise matrix
of owner family, phase, and failure class. Each family appears in normal,
rollback where applicable, lost-ack, and shutdown pairings, but no full
owner-entry-path by phase by failure-class Cartesian product is required. A
single synthetic oneshot test is necessary but insufficient.

### Rejected alternatives

- **Timeout around the outer apply future.** Dropping that future can detach or
  cancel the only code capable of rollback and does not prove settlement.
- **Abort or drop the transaction `JoinHandle`.** A dropped Tokio handle
  detaches its task; aborting it reintroduces the split-apply hazard ADR-0080
  forbids.
- **Release admission at the response deadline.** That allows a second
  candidate to overlap a still-owned transaction and breaks the one-candidate
  contract.
- **Add a second semaphore.** Parallel admission hides the stuck owner without
  restoring coordinator liveness or a trustworthy outcome.
- **Put independent timeouts around post-mutation oneshot replies.** Local
  timeout errors cannot distinguish an unprocessed command from a completed
  side effect whose reply was lost. They can trigger rollback races and false
  terminal claims. The aggregate watchdog instead fails stop when settlement
  cannot be proved.

## Consequences

- A permanently stuck owned transaction becomes a bounded daemon restart
  instead of an indefinite config-plane wedge.
- Systemd and other supervisors must treat exit 70 as failure and restartable.
  Deployment documentation and shipped supervisor examples must be updated as
  part of implementation; this ADR makes no portable supervisor claim.
- The bound is deliberately fail-stop, so BGP sessions can be interrupted after
  a severe control-plane ambiguity. Supervision and graceful-restart behavior
  mitigate but do not erase that operational cost.
- Healthy applies retain cancellation shielding and one-candidate admission.
  They pay one operation record, one watchdog registration, phase updates, and
  bounded telemetry; the data-plane executor path gains no per-command timer.
- Operators get a precise operation ID and phase for the last 30 minutes before
  fail-stop without exposing candidate or authorization material.
- [ADR-0076](0076-config-transaction-model.md) remains authoritative for
  authorization tiers, optimistic tokens, one-candidate planning,
  mutation-family validation, persistence, rollback, ambiguity fencing, and
  commit-confirm authority.
  [ADR-0080](0080-cancellation-shielded-runtime-applies.md) remains
  authoritative for cancellation shielding. This ADR adds a terminal liveness
  bound; it does not weaken either contract.
- No public API or protobuf change is required. Internal readiness wiring,
  mutation fencing, supervision, metrics, and subprocess recovery tests are
  required before this ADR can be accepted or the underlying issue called
  fixed.
