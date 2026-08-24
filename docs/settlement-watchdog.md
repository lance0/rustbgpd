# The Settlement Watchdog

Operator reference and runbook for the runtime-config settlement
watchdog: the mechanism by which the daemon deliberately exits with
status 70 when it cannot prove that a persisted config mutation
settled. The decision record is
[ADR-0127](adr/0127-config-transaction-settlement-watchdog.md); the
authoritative implementation is
`crates/api/src/runtime_config_settlement.rs` and the per-owner wiring
around it. If this page and the code disagree, the code is right —
file an issue.

If you are here because the daemon just exited 70, skip to
[the runbook](#runbook-the-daemon-exited-70--what-now).

---

## Why the daemon deliberately exits

Every persisted runtime-config mutation — a config transaction, a
neighbor add, a policy edit, a SIGHUP reload — runs as one daemon-wide
operation under one shared coordinator
([ADR-0076](adr/0076-config-transaction-model.md)), and the mutation
itself is shielded from caller cancellation
([ADR-0080](adr/0080-cancellation-shielded-runtime-applies.md)): a
client that disconnects or times out cannot abort a half-applied
change. That shielding is what makes mutations safe, but it creates a
liveness obligation. After taking ownership, the executor awaits actor
replies, persistence acknowledgements, rollback acknowledgements. If
one of those replies is lost, nothing else in the daemon can take the
coordinator back: the config plane is wedged while the process keeps
reporting healthy.

The watchdog closes that gap with a deliberately blunt contract: an
owned mutation either **proves** it settled — success, a proven
no-effect rejection, or a fully acknowledged rollback — or the daemon
**fences** (readiness fails, new mutations are rejected) and exits
with status 70 so the supervisor restarts it. The daemon never guesses
which side of an unacknowledged mutation completed. The restarted
process reconstructs authority from durable state — the atomically
published config file and, for commit-confirmed transactions, the
config-adjacent locator — which is the one thing that can decide.

Exit 70 is therefore not a crash. It is the daemon concluding that a
restart under supervision is the only trustworthy way forward, and
arranging for that restart to be safe.

## What operations are owned

Six owner families take the coordinator and are covered by the
watchdog:

| Family | Operations |
|---|---|
| Config transactions | Unary and streamed `ApplyConfigTransaction`, `RollbackConfigTransaction`, `ConfirmConfigTransaction`, `AbortConfigTransaction`, the timeout auto-revert, and gNMI `Set` (ordinary, commit-confirmed, confirm, cancel, set-rollback-duration) |
| SIGHUP reload | The whole reload, from post-acquire validation through peer reconciliation, config-bridge/persister adoption, tracing, and gNMI dial-out acknowledgement |
| Neighbors | Static and dynamic neighbor Add/Delete |
| FIB tables | `SetFibTable`, `DeleteFibTable` |
| Peer groups | Group Set/Delete and neighbor membership Set/Clear |
| Policy | Policy and neighbor-set Set/Delete, global import/export chain Set/Clear, per-neighbor import/export chain Set/Clear |

Read-only operations — Plan, Status, History, Get, List — never take
ownership and are outside the watchdog. The shutdown/warm-checkpoint
coordinator acquisition is a fence, not a mutation owner.

## Two clocks: acquisition and settlement

Two separate bounds apply, and they mean very different things:

- **Pre-ownership (10 minutes, Apply only).** A unary or streamed
  `ApplyConfigTransaction` waits at most ten minutes to acquire the
  coordinator. Expiry returns `DEADLINE_EXCEEDED` with the message
  that "coordinator ownership was not acquired and apply did not
  begin" — a clean rejection with **no daemon effect**. Nothing was
  mutated; retry once the current owner settles. This bound covers
  only Apply: SIGHUP and the neighbor/FIB/peer-group/policy RPCs have
  no pre-ownership timeout and queue until the coordinator frees.
- **Post-ownership (30 minutes + 5 seconds, every owner).** The moment
  an operation acquires the coordinator, one fixed, non-resettable
  30-minute settlement budget arms. An owner that cannot prove
  settlement by then is recovery-fenced, and the process exits 70
  after a five-second grace. The grace exists solely to propagate the
  fence (fail readiness, close mutation admission) and emit one
  bounded diagnostic — it is not a rollback window.

From the moment an Apply begins waiting for the coordinator, consuming
both bounds in sequence therefore takes 40 minutes 5 seconds to reach
fail-stop, without anything being wrong with the watchdog itself. For
a streamed apply, the candidate upload precedes that wait and is
separately bounded at 30 minutes by the stream's total timeout, so the
full RPC-start-to-fail-stop worst case is about 70 minutes 5 seconds.

While an owner is live, the daemon logs a
`runtime config settlement budget warning` at 15, 25, and 29 minutes
elapsed (`remaining` = `15_minutes`, `5_minutes`, `1_minute`). The
warnings never extend or reset the deadline. An owner still running at
15 minutes is already far outside normal latency — see
[the budget rationale](#the-constants-are-fixed-by-design) — so treat
the first warning as the moment to start looking, not the 29-minute
one.

## The owned phases

Ownership moves through exactly three live phases, advancing
monotonically, and every settlement log line names the current one:

| Phase | Meaning |
|---|---|
| `owned_preflight` | Side-effect-free checks after acquiring the coordinator: re-planning, token comparison, mutation-family validation. Nothing has changed yet. |
| `mutating` | The first reversible runtime or journal mutation has begun. |
| `settling_rollback` | Persistence, finalization, confirmation-state publication, or a compensating rollback is in progress. |

Before any of these, a queued request is in a pre-watchdog
waiting-for-ownership state: validated, but with no coordinator guard
and no mutation authority. A request rejected there — including the
ten-minute Apply acquisition timeout, and every request still queued
when a fail-stop or shutdown closes the coordinator — had no effect.

A live phase terminates through exactly one of two branches: clean
settlement (which releases the coordinator) or recovery fencing (which
retains it until process death). There is no third outcome, and a late
reply arriving after the fence has won cannot reverse it.

## The five fence reasons

The fail-stop diagnostic names one `fence_reason`. In plain language:

| `fence_reason` | What happened | What the restart will find |
|---|---|---|
| `budget_expired` | 30 minutes passed without proof of settlement — an actor, persistence, or rollback reply never arrived. | Unknowable from the old process. Durable state decides: whichever config the atomic rename left published is validated and adopted at boot. |
| `executor_lost` | The daemon-owned task running the mutation died (panic, unwind, abort) after taking ownership. Fail-stop advances to five seconds after the loss rather than waiting out the budget. | Same as `budget_expired`: boot decides from durable state. |
| `known_divergence` | The daemon *knows* runtime and durable state diverged and cannot repair it in place: a compensating rollback failed, a torn-down session identity cannot be restored, or finalization of a durably published candidate failed. | Not ambiguous — the on-disk authority is known — but the runtime could not be brought back to match it. The restart rebuilds the runtime from disk. |
| `publication_ambiguous` | The candidate config was renamed into place, but the directory fsync that proves durability did not complete. The complete candidate is visible at the target; the daemon adopted it and did not roll back. | Expect the **new** candidate to be the boot authority. Startup validates the published object and fails closed if it is invalid. |
| `acknowledgement_lost` | A mutation, persistence, or finalization command was accepted, and the reply proving completion was lost. Done and not-done are indistinguishable. | Either config may be authoritative. Boot decides; verify before re-issuing (see the runbook). |

The common rule across all five: no success or clean-failure claim
without proof, no rollback guessing, and after the restart it is the
durable state — not your memory of the RPC's last response — that says
which config is live. `publication_ambiguous` and
`acknowledgement_lost` in particular mean the mutation **may have
completed**; blind re-issue is how you apply a change twice.

Contrast this with everything that does *not* fence: parse failures,
plan rejections, precondition failures, the acquisition timeout, and
any failure before the first mutation are clean rejections — the
daemon keeps running on the old config and an immediate retry is safe.

## The constants are fixed by design

The 30-minute budget, five-second grace, and exit status 70 are fixed
implementation contracts, not config knobs, and the shipped supervisor
values are derived from them:

- **30 minutes is a receipt-based ceiling, not a latency promise.**
  The sealed
  [IRR transactional-apply receipt](perf/irr-transactional-apply-2026-08.md)
  measured a ~295.6 MB streamed candidate (320 route-server members ×
  183,040 routes) completing end-to-end in at most 208.55 seconds,
  with timeout auto-revert of the same generation completing within
  69.5 seconds. Thirty minutes is roughly 8× the worst measured
  legitimate settlement — an owner that reaches the budget is wedged,
  not slow.
- **The budget is non-resettable** because a resettable budget is
  defeated by exactly the failure it exists to catch: a livelocked
  owner that keeps emitting signs of life without ever settling would
  extend itself forever. Only proved settlement disarms the clock.
- **The fatal clock is an independent OS thread**, prestarted at
  daemon boot, that does not depend on the Tokio runtime, the mutation
  executor, readiness propagation, logging, metrics, or any lock those
  paths hold. The terminal action is a bare `_exit(70)` — no handlers,
  no unwinding, no allocation — so nothing a wedged owner is stuck on
  can postpone it.
- **`TimeoutStopSec=32min` in the shipped unit** exists so systemd
  never SIGKILLs a legitimately settling transaction: an explicit
  `systemctl stop` on a daemon that owns a mutation waits for
  settlement or the watchdog (30 minutes + 5 seconds), and 32 minutes
  covers that with margin. Making the budget tunable would silently
  break this derivation, which is why it is not a knob.

---

## Runbook: the daemon exited 70 — what now?

**When this is you:** the unit restarted unexpectedly (or is down) and
`systemctl status rustbgpd` shows `code=exited, status=70`.

### 1. Confirm it was a settlement fail-stop

```bash
systemctl status rustbgpd
journalctl -u rustbgpd -g 'settlement' --since -2h
```

The authoritative signature is one ERROR line from the old process:

```
runtime config settlement fail-stop armed
```

with fields `operation_id`, `kind`, `phase`, `elapsed_seconds`,
`budget_seconds`, `response_attached`, `terminal="recovery_fenced"`,
`fence_reason`, and `exit_status=70`. In daemon mode no other path
exits 70, and no fail-stop happens without this line. Reading it:

- `kind` names the owner family (`sighup`, `apply`, `confirm`,
  `neighbor_add`, `policy_set`, …) and `phase` names how far it got
  (`owned_preflight` / `mutating` / `settling_rollback`).
- `fence_reason` is the diagnosis — see
  [the table above](#the-five-fence-reasons). `elapsed_seconds` near
  1800 with `budget_expired` is a silent wedge (expect the 15/25/29
  minute `runtime config settlement budget warning` lines before it);
  a small `elapsed_seconds` with any other reason is a detected
  ambiguity, fenced within seconds of the failure.
- `response_attached=detached` means no live RPC response waiter
  existed at the fence — the caller had disconnected, or the operation
  was daemon-initiated (SIGHUP, auto-revert). It does not weaken
  anything; it explains why no client saw an error.
- `operation_id` is a daemon-generated correlation ID, meaningful only
  for matching this process's own log lines.

The diagnostic deliberately carries no config contents, paths, tokens,
confirm IDs, or raw error text; `kind` + `phase` + `fence_reason` are
the complete classification.

The Prometheus `RustbgpdRestarted` alert can reveal a sampled change in
`process_start_time_seconds` for the stable rustbgpd scrape target. It covers
the restart after the five-second supervised-recovery gap, but it is not proof
of a settlement fail-stop: planned, manual, package, and crash restarts fire as
well. The registered collector requires readable, usable Linux `/proc` process
data; inaccessible data can omit the family, while unusable boot or stat data
can leave start time zero and prevent the alert from establishing a restart.
Missing samples on either side of the restart or a target-label change can
also miss it, and it expires after the ten-minute lookback. The metric cannot
attribute exit 70 or any restart reason; the settlement log above and systemd
remain authoritative.

### 2. Let the restart happen — it is safe by design

The shipped unit restarts the daemon after `RestartSec=5`. Restart is
the *intended* recovery, not a risk to be managed: the process exited
precisely because it could not decide what state it was in, and the
new process does not inherit that ambiguity — it validates the one
atomically published config object on disk and fails closed if that
object is invalid. Do not mask exit 70 as success or suppress its
restart in a supervisor override.

### 3. Check which config authority booted

The mutation that fenced may or may not have landed. Establish which:

- **Commit-confirmed transaction pending?** If a confirmed apply was
  in flight, its durable authority is the config-adjacent locator
  (`<config>.commit-confirm-locator.json` beside your config file;
  format inventory in
  [format-version-namespaces.md](format-version-namespaces.md)). A
  locator retained across the restart triggers the verified **boot
  revert**: the daemon reverts to the pre-transaction config, saves
  the unconfirmed candidate aside, and says so loudly — an ERROR log
  line and a `!! commit-confirm boot revert` stderr banner naming the
  confirm ID. If you see that banner, your last confirmed apply was
  undone; its candidate is preserved beside the recorded target for
  inspection and re-apply.
- **Ordinary mutation?** Compare the running daemon against what you
  intended:

  ```bash
  rbgp config diff /path/to/intended-candidate.toml
  ```

  Exit 0 means no differences — the fenced mutation completed and the
  candidate is live. Exit 2 means differences remain — it did not
  land (or landed partially in a `known_divergence` case); the diff
  output is exactly what a fresh apply would change. This
  re-plan-and-compare step is the supported recovery for an Apply
  whose response was lost; there is no per-operation status record to
  query for ordinary applies. Do not re-issue the mutation until the
  diff tells you it is still needed.

### 4. Know what the restart did to your BGP sessions

A fail-stop restarts the process, and the session cost is real. The
graceful-restart mitigation is exactly as strong as each peer's
negotiated GR capability shape — no stronger. The M85 receipt
([INTEROP.md](INTEROP.md)) measured both shapes against BIRD 2:

- A peer with a **real two-sided GR capability** (BIRD
  `graceful restart on`: address families listed in the capability)
  has its routes held stale-preserved through the restart — zero
  withdraws toward surviving peers until re-establish plus the
  End-of-RIB sweep.
- A peer with BIRD's **default** `graceful restart aware` still sends
  the GR capability, but with restart time 0 and no address families:
  the restart produces **immediate withdraws with nothing preserved**.

Independently of the wire shape, the restarted daemon rebuilds its
full RIB from its peers: the optional bounded shutdown checkpoint
(see the graceful-restart row in [ROADMAP.md](../ROADMAP.md)) shipped
as publication only, without boot restore/adoption. Even a fully
GR-mitigated fail-stop pays complete reconvergence. Audit which of
your peers actually negotiate two-sided GR before assuming the
mitigated case.

### 5. Decide whether to page

- **One fail-stop, clean restart, authority verified:** an incident to
  understand (pull the fence reason and the owning operation's log
  trail), not an emergency. A lost acknowledgement under extreme load
  or a transient storage error can legitimately produce one.
- **Repeat fail-stops:** the unit caps recovery at
  `StartLimitBurst=5` starts per `StartLimitIntervalSec=10min`. Five
  failures inside ten minutes leave the unit **down** in
  start-limit-hit state — that is a page. A deterministic fault (an
  unwritable config directory, a broken read-only bind mount, a
  failing disk) will re-fence every attempt; the rate limit exists so
  it cannot flap every five seconds forever. Fix the root cause,
  then:

  ```bash
  sudo systemctl reset-failed rustbgpd
  sudo systemctl start rustbgpd
  ```

  Note the deliberate arithmetic: only fast-failing starts can trip
  the limit. A wedge that consumes its full 30-minute budget can never
  reach five starts in ten minutes — the start limit bounds fast
  deterministic failures, while the watchdog bounds each slow wedge.

### 6. If the daemon is fenced but has not exited yet

Between the fence and the exit (normally five seconds; up to the
budget for an owner that has not yet fenced), the daemon is already
telling you: `/readyz` fails with
`runtime config settlement requires supervised recovery`, and every
new persisted mutation is rejected. There is nothing to rescue — a
fence cannot be reversed in a live process, and settlement commands
from the fenced owner can no longer claim success. Let it exit. An
explicit `systemctl stop` in this window follows the same path and
still ends in exit 70, not a clean shutdown; with a healthy
still-settling owner, `stop` legitimately takes up to the watchdog
deadline — that wait is the daemon refusing to abandon a mutation
mid-flight, and `TimeoutStopSec=32min` is sized for it.

---

## The supervisor contract

The shipped unit
([examples/systemd/rustbgpd.service](../examples/systemd/rustbgpd.service))
encodes the contract, and
`scripts/check_release_install_contract.py` enforces these exact
values at release time:

| Directive | Value | Why |
|---|---|---|
| `Restart` | `on-failure` | Exit 70 must be restartable: the restart *is* the recovery. Exit 0 is reserved for operator-initiated shutdown and does not restart. |
| `RestartSec` | `5` | Prompt retry for transient failures. |
| `StartLimitIntervalSec` / `StartLimitBurst` | `10min` / `5` | Bound repeated fail-stop recovery so a deterministic fault ends in a visibly failed unit instead of an infinite flap. |
| `TimeoutStopSec` | `32min` | An explicit stop waits through the full 30-minute settlement budget plus the 5-second grace; systemd must never SIGKILL a legitimately settling transaction. |

Two anti-patterns the release checker also rejects: listing 70 in
`SuccessExitStatus` (masks the failure) or in
`RestartPreventExitStatus` (defeats the recovery). If you maintain
your own unit or another supervisor, carry all four rows; the Docker
equivalent of the stop bound is `--stop-timeout=1920`
([QUICKSTART.md](QUICKSTART.md)). The full unit walkthrough, including
the non-watchdog exit codes (0 operator shutdown, 1 unrecoverable
component failure), is in [deployment.md](deployment.md#systemd).

## SIGHUP under the watchdog

SIGHUP reload is a first-class watchdog owner (`kind=sighup`,
detached), with a few semantics of its own:

- **One reload at a time.** A SIGHUP arriving while a reload is in
  flight is logged (`SIGHUP received while previous reload still in
  flight; ignoring`) and dropped — re-send it after the current one
  settles. SIGHUP has no pre-ownership timeout: it waits for the
  coordinator, so a long-running owned transaction delays it.
- **Preflight rejections stay cheap.** A pending commit-confirm, a
  parse failure, an outbound prefix-limit preflight rejection — all
  reject before ownership does any work: clean no-effect, old config
  keeps running, fix and re-signal. The
  [reload matrix](reload-matrix.md) still governs which fields a
  reload can apply at all.
- **Partial convergence is normal and settles cleanly.** A reload that
  halts at a step failure produces an authoritative *known-partial*
  receipt: the runtime snapshot, config bridge/persister, tracing, and
  gNMI dial-out targets all adopt the same partial authority, the
  owner settles, and the daemon logs `SIGHUP settled with an
  authoritative partial runtime receipt`. Fix the failing TOML and
  reload again. Partial is a clean outcome — only an *unprovable*
  outcome fences.
- **What changed versus the pre-watchdog daemon:** a reload whose
  acknowledgements are lost, or whose reconcile result is not
  authoritative, now fences and exits 70 instead of logging an error
  and carrying on with a runtime that may not match what any surface
  reports. And coordinated shutdown no longer races an in-flight
  reload: it closes new admission, then waits on the owner's registered
  deadline and pre-armed, monotonically shortened fatal boundary. Timed
  condition-variable waits always recheck the registry and the shutdown
  wait returns only after the registry proves there is no owner. If the
  owner reaches its budget, the waiter fences it as `budget_expired`,
  preserves the five-second recovery-fence grace, and invokes the same
  exit-70 boundary as the independent fatal clock. It never falls through
  to checkpointing or actor teardown with an active owner. This bounds the
  settlement wait itself; it does **not** establish a finite aggregate time
  to the first BGP Cease because a clean owner may use its full budget and
  later checkpoint and drain stages retain their own bounds.

## Related pages

- [ADR-0127](adr/0127-config-transaction-settlement-watchdog.md) —
  the decision record: full authority/compensation matrix and
  acceptance evidence
- [OPERATIONS.md](OPERATIONS.md#runtime-config-settlement-fail-stop)
  — the settlement fail-stop in the production reference, including
  the readiness and telemetry surface
- [deployment.md](deployment.md#systemd) — the shipped unit end to
  end
- [reload-matrix.md](reload-matrix.md) — what SIGHUP and runtime CRUD
  can apply per config field
- [format-version-namespaces.md](format-version-namespaces.md) — the
  commit-confirm locator among the daemon's durable formats
