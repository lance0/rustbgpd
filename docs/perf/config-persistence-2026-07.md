# Config persistence, history, rollback, and commit-confirm receipt — 2026-07

This receipt answers one bounded question: do the mutating config paths — the
persisted write, the applied-config history, `config rollback`, and the three
commit-confirm outcomes — actually behave as specified against a real daemon
with real BGP sessions attached? Three real sessions exchange real
OPEN/KEEPALIVE/UPDATE messages with a real rustbgpd over loopback, and the
config file, the runtime snapshot, the history, the Prometheus series, and the
wire are all read back at every phase boundary.

It exists because none of this had integration coverage. Every mutating RPC
was unreachable in a shipped deployment until the quick-start stopped mounting
the config read-only, so the entire area had unit tests and nothing else.

It is a behavior receipt, not a timing one. There is no host-quiescence
preflight, no distribution is collected, and no performance claim follows from
it.

**Verdict: green at the measured commit.** A persisted mutation reaches disk,
the runtime, and the history and survives a restart on every surface including
the sessions. `config rollback` restores a prior generation without resetting a
session. A commit-confirmed transaction sticks when confirmed, auto-reverts on
its deadline when it is not, and after a SIGKILL inside the confirmation window
comes back in a defined state rather than a torn one. An injected persistence
failure is refused while runtime config, session identity, flap state,
cumulative counters, metric series, and wire state are all left unchanged
rather than restored. The persisted file, the runtime snapshot, and the history
record agree at every boundary.

**Measured commit:** `6a49f0963c9d30a7866ebf5a413090a5fb4090b5`

**Result:** 109 of 109 precommitted checks pass (105 harness checks, 0 failed;
4 driver log gates, 0 failed). Zero stub decode errors on daemon UPDATEs. Wall
clock 27 s.

An earlier run of this same scenario, with the same harness and the same
assertions, was published red at 105 of 109. All four failures were one defect,
and it was not in the config plane: the BGP listener bound without
`SO_REUSEADDR`, so a restart performed while a socket the previous generation
had accepted was still in `FIN_WAIT`/`TIME_WAIT` failed `EADDRINUSE` — and the
daemon did not exit, it marked itself not-ready and kept answering gRPC,
holding its config, and reporting its peers while refusing every inbound BGP
connection. Both of this receipt's restarts hit it. The option is now set before
bind, and a bind failure now exits 1 rather than parking the process with its
core function dead behind a healthy-looking management plane. The four checks
that could not be made are made below. The harness and its assertions are
unchanged between the two runs; the score moved because the code was fixed.

## Disclosed shape

The shape is pinned in the harness as constants, so this section describes the
run that was performed rather than a configurable intent.

| | |
|---|---|
| Peers | 3 real BGP sessions (1 route source, 2 observers) |
| Families | IPv4 unicast and IPv6 unicast; nothing else negotiated |
| Add-Path | not negotiated on any session |
| Table | 6 IPv4 `/24`s + 3 IPv6 `/64`s, originated by one source peer |
| Local ASN | `65500`, all peers eBGP with distinct remote ASNs |
| Policy | none configured |
| Deployment | **writable config**: a template copied into the daemon's own state volume, the pattern the quick-start and container images now ship |
| Config directory | separate from the runtime state directory, so sealing one does not seal the other |
| Daemon generations | 3 (cold start, SIGTERM restart, SIGKILL restart) |
| Repetition | **single run, one host, one commit** |

| stub | role |
|---|---|
| `127.9.2.1` | route source (originates the table) |
| `127.9.2.2` | **subject** — the session a rejected mutation must leave untouched |
| `127.9.2.3` | **bystander** — an unrelated session that must also be undisturbed |

Six further neighbors are added, rolled back, confirmed, timed out, killed
mid-window, and refused. None of them is ever dialed: they exist to be written,
restored, reverted, and refused.

Phase order is deliberate and load bearing. Everything that needs the original,
never interrupted sessions runs **before** the first restart, so a restart-path
failure cannot silently weaken the rejected-mutation evidence. The order run
was: baseline → rejected mutation → history and rollback → commit-confirm
success → commit-confirm timeout → persist and clean restart → commit-confirm
SIGKILL inside the window.

The bystander is the non-vacuity sentinel for the rejection phase. The
`uptime_seconds` / `messages_*` / `updates_sent` precondition is the
non-vacuity sentinel for the word "untouched": at uptime 0 with no messages
exchanged, an untouched session and a freshly rebuilt one are
indistinguishable, and every assertion in that phase would hold for both. The
run therefore lets the sessions age first and asserts the precondition
explicitly — it recorded `uptime_seconds=5`, `messages_received=2`,
`messages_sent=6`, `updates_sent=4` before sealing anything.

## What holds

### 1. Persistence and restart recovery

| Precommitted check | Result |
|---|---|
| `rbgp neighbor <addr> add` accepted against a writable config | exit 0 |
| Neighbor present on disk after the mutation, absent before | yes / yes |
| Neighbor present in the runtime peer list | yes |
| History grew by exactly one entry | 7 → 8 |
| Staged temp file left behind | none |
| Restarted daemon is a new process | yes |
| Restarted daemon's BGP listener bound | bound |
| Sessions re-established and the wire reconverged | 0.051 s (single observation) |
| Config bytes unchanged by the restart | identical sha256 |
| Neighbor still in the runtime after the restart | yes |
| Disk / runtime / history agreement after the restart | holds |

The persisted mutation survived the restart on every surface, and so did the
sessions: all three stubs redialled and both observers were back to the full
6 + 3 table 51 ms after the daemon answered its first gRPC call.

### 2. History and rollback

| Precommitted check | Result |
|---|---|
| History indexes dense and newest first | holds |
| Retained entries have distinct content digests | holds |
| Newest retained entry is byte-for-byte the file on disk | holds |
| `rbgp config rollback 1` accepted | exit 0 |
| Rolled-back neighbor gone from disk | yes |
| Rolled-back neighbor gone from the runtime | yes |
| **Earlier neighbor still present on disk and in the runtime** | yes / yes |
| Disk neighbor set equals the restored generation's | equal |
| Session reset by the rollback | none (0 link drops, 0 NOTIFICATIONs, still Established) |
| Disk / runtime / history agreement after the rollback | holds |

The "earlier neighbor still present" rows are the non-vacuity pair: without
them, "the rolled-back neighbor is gone" would be indistinguishable from a
rollback that emptied the file.

### 3. Commit-confirm

**Confirmed.** `config apply --confirm-id --confirm-timeout` reported
`pending`, the revert journal appeared, the candidate was on disk inside the
window, `config confirm` was accepted, the journal was consumed, `config
status` moved to `confirmed`, and the candidate is on disk and in the runtime
afterwards. Agreement holds at that boundary.

**Timed out.** The unconfirmed transaction auto-reverted **10.009 s** into a
10 s window (single observation). `config status` reported `auto_reverted`, the
journal was consumed, the runtime dropped the candidate, and the disk neighbor
set went back to the pre-commit generation. No session was reset.

**SIGKILLed inside the window.** This is the case the receipt was built for.
With a 600 s confirm window open and the journal on disk, the daemon was
SIGKILLed and restarted. It came back in a defined state:

| Precommitted check | Result |
|---|---|
| Revert journal written before the kill | yes |
| Candidate on disk before the kill | yes |
| Daemon booted after SIGKILL | yes |
| Restarted daemon's BGP listener bound | bound |
| Sessions re-established and the wire reconverged | 0.051 s (single observation) |
| Revert journal consumed by the boot revert | yes |
| Unconfirmed candidate saved aside to `<config>.unconfirmed` | present, and holds the candidate |
| Disk reverted to the pre-commit config | yes |
| Disk neighbor set equals the pre-commit generation | equal |
| Runtime reverted to the pre-commit config | yes |
| Pending confirmation after boot | none (`status: none`) |
| Recovered config passes a real `rustbgpd --check` | exit 0 — not torn |
| Boot-revert banner in the log, naming the transaction | exactly 1 |

Nothing about the confirmation window was torn: the journal, the saved-aside
candidate, the reverted file, the reverted runtime, and the cleared
confirmation state are all mutually consistent, the recovered file revalidates,
and the sessions came back onto a daemon running the pre-transaction config.

The single boot-revert banner is also an absence assertion: the clean SIGTERM
restart in phase 1 must not produce one, and did not.

### 4. Injected persistence rejection

The config directory was sealed to `0o500` — the persistence failure an
operator hits on a read-only or root-owned config mount, and the same injection
the unit tests use. Both a `delete` of the live subject session and an `add` of
a new neighbor were then attempted.

Both were refused with `precondition failed: config persistence failed: failed
to write <config dir>/config.toml: Permission denied (os error 13)`.

`FAILED_PRECONDITION` means the request did nothing, so every row below is
asserted as **unchanged**, not restored:

| Surface | Precommitted check | Result |
|---|---|---|
| Runtime config | Peer set unchanged | 3 peers, identical set |
| Runtime config | Refused add created no peer | none |
| Session identity | Address / state / remote ASN unchanged | `127.9.2.2` / `Established` / `64702` |
| Session identity | Still Established | yes |
| Flap state | `flap_count` unchanged | 0 → 0 |
| Flap state | `notifications_sent` unchanged | 0 → 0 |
| Counters | `uptime_seconds` did not rebase | 5 → 10 (a rebuild restarts at 0) |
| Counters | `updates_sent` did not rebase | 4 → 4 |
| Counters | `messages_received` / `messages_sent` did not rebase | 2 → 2 / 6 → 6 |
| Metric series | `bgp_messages_received_total` / `_sent_total` did not rebase | 2 → 2 / 6 → 6 |
| Metric series | `bgp_session_established_total` unchanged | 1 → 1 |
| Metric series | `bgp_session_flaps_total` unchanged | absent → absent |
| Metric series | `bgp_session_state_transitions_total` unchanged | 6 → 6 |
| Metric series | bystander's `bgp_session_established_total` unchanged | 1 → 1 |
| Wire | Subject wire identity unchanged | 6 v4 / 3 v6, 9 announced, **0 withdrawn**, 4 UPDATEs, 0 NOTIFICATIONs, **0 link drops**, established |
| Wire | Bystander wire identity unchanged | identical tuple |
| Disk | Config bytes unchanged | identical sha256 |
| Disk | No staged temp file left | none |
| Disk | History did not grow | 1 → 1 |
| Recovery | A mutation succeeds again once the directory is writable | exit 0, landed on disk |
| Log | Subject named on a `peer deleted` line in that generation | 0 |

The distinction between "unchanged" and "restored" is the whole point, and the
counters are what carry it. An implementation that applied and then compensated
would leave the peer address present and the config file byte-identical — both
of those rows would still pass — while `uptime_seconds` restarted at 0,
`bgp_session_established_total` incremented, `bgp_session_flaps_total` appeared,
and the stub's `link_drops` went to 1. None of that happened.

`bgp_session_flaps_total` reading **absent** in both scrapes rather than `0` is
load bearing: a reaped-and-restarted series is a visible mutation even when the
value looks similar, so the harness distinguishes an absent series from a zero
one.

### 5. Agreement between the file, the runtime, and the history

Closed at seven boundaries: baseline, post-rejection recovery, rollback
precondition, rollback, confirm, persist, and restart.

- **Disk to history, byte level.** After every daemon write, the newest
  retained history entry's embedded SHA-256 equals the SHA-256 of the config
  file. The persister serializes one string and uses it for both, and the run
  confirms it end to end at six boundaries.
- **Disk to runtime, semantic.** `rbgp config effective` is canonicalized and
  secret-redacted, so it legitimately reformats; its neighbor set equals the
  file's at every boundary.
- **Disk revalidates.** The persisted file passes a real `rustbgpd --check` at
  every boundary, including the one recovered by the boot revert.

One deliberate divergence is disclosed rather than asserted away. At **boot**,
before any daemon write, the newest history entry is the serialized *runtime*
snapshot rather than the operator's file bytes — re-reading the source there
would race an operator edit made between startup validation and the persister
task starting. The two documents are semantically equal but not byte-equal, and
the receipt asserts the semantic equality at that one boundary and byte
equality everywhere after.

## What this receipt does not cover

Stated as plainly as what it does:

- **Restart recovery beyond an immediate redial.** Both restarts are now
  observed end to end, but the stubs reconnect at once and no Graceful Restart
  is configured. Nothing here speaks to GR/LLGR stale-route preservation across
  a restart, to a peer that does *not* reconnect promptly, or to recovery with
  a real table behind it.
- **Restart over sockets left by an older binary.** `SO_REUSEADDR` has to be
  set on both generations, so the first restart of a daemon whose previous
  generation predates the fix can still be rejected. Every generation in this
  run is the measured binary, so that upgrade-boundary case is not exercised.
- **The bind-failure exit path.** A bind failure now exits 1 rather than
  running on not-ready. No generation in this run failed to bind, so that
  disposition is not driven here; it stays a unit-level and integration-test
  contract.
- **Scale.** Three peers, 9 prefixes, a config file with fewer than a dozen
  neighbors, and a history that never approaches the 20-entry retention bound.
  Nothing here speaks to history eviction, a large config's serialization cost,
  or persistence under concurrent mutation load.
- **Repetition.** One run, on one host, at one commit. The elapsed numbers
  reported (50.9 ms cold convergence, 51 ms after each restart, 10.009 s
  auto-revert) are single observations, not medians.
- **Concurrency.** Every mutation is issued serially by one client. The
  single-outstanding-stage rule, the pending-confirm fence that makes other
  mutators return `FAILED_PRECONDITION`, and racing mutators are not exercised.
- **The other 18 persisted mutators.** Only `AddNeighbor`, `DeleteNeighbor`,
  `ApplyConfigTransaction`, and `RollbackConfigTransaction` are driven. The
  peer-group and policy RPCs share the same two-phase seam but are not
  exercised here, and the wire-history argument that motivated the change for
  them — a forward apply that bounces inheriting members or puts a Route
  Refresh on the wire — is therefore not proved end to end.
- **Single-phase holdouts.** FIB-table CRUD and the transaction executor
  deliberately keep single-phase persistence with their own rollbacks. Neither
  is driven, and their ambiguous-outcome reporting is untested here.
- **Failure modes other than an unwritable directory.** A full filesystem, an
  I/O error mid-fsync, a read-only remount between stage and commit, and a
  crash *between* the stage and the rename are not injected. Only `EACCES` on
  the directory is.
- **Journal corruption paths.** `boot_revert_check` refuses a non-regular,
  oversized, torn, or unusable journal, and fails closed when the journal
  cannot be removed after a successful revert. This run only drives the healthy
  revert; the refusal branches stay unit-level contracts.
- **A pre-existing `<config>.unconfirmed`.** The save-aside never has to avoid
  overwriting an earlier one.
- **Symlinked configs.** `boot_revert_check` canonicalizes a symlinked config
  so the revert updates the target and preserves the link. The deployment here
  uses a plain file.
- **Rollback beyond index 1**, and rollback to a generation that differs by
  more than one neighbor.
- **Restart-required config changes.** Every mutation in this run is
  reload-applied. A rollback or transaction that crosses a restart-required
  field is not driven.
- **Secret handling.** No `md5_password` or TCP-AO key is configured, so the
  redaction boundary between the effective dump and the persisted file is never
  put under load. That is also why the disk-to-runtime comparison is semantic.
- **Non-loopback and multi-host deployments**, containers, and the actual
  shipped image's volume layout. The template-copy *pattern* is exercised; the
  shipped Compose file is not.

## Method and gates

`bench/scale/config-persistence/run-receipt.sh` takes no arguments, refuses a
dirty checkout, and refuses to run as root — uid 0 ignores the `0o500` seal,
which would make the entire rejection phase vacuous. It records provenance and
binary hashes, builds the daemon, CLI, and harness with `--release --locked`,
emits the config template, copies it into the writable state volume, and runs
the result through a real `rustbgpd --check` before measuring.

It also refuses to start while the BGP listen port is still held by a listener
or a lingering `TIME_WAIT` entry from an earlier run, so a published run always
has a clean first generation and any later bind failure is attributable to the
restart rather than to the environment.

Unlike the sibling receipts, the **harness** owns the daemon process: three of
the five areas only exist across a restart. It waits for a real gRPC round trip
after each start, and redialling the stubs is deliberately a separate,
non-fatal step so a daemon that came back without a usable listener is reported
as a named failing check instead of aborting the run. That separation is what
produced the listener finding on the earlier run: the config-plane assertions in
both restart phases still passed and were still published while the transport
defect was named.

Each assertion prints one `CHECK <name> <PASS|FAIL> <detail>` line. Phase gates
after cold convergence are non-fatal, for the same reason the ADR-0113 receipt
made them non-fatal: a receipt that aborts on its first failure hides the rest
of the picture.

The driver then applies four log gates the harness cannot see: exactly one
boot-revert banner across the whole run (the clean SIGTERM restart must not
produce one), exactly one banner naming the killed transaction, zero `peer
deleted` lines naming the subject in the generation that runs the rejection
phase, and zero panics.

The run is accepted only when every harness check and every log gate passes. At
the measured commit it is accepted.

## Reproduce

On a Linux host with loopback addresses and ports 17910/19189 free (including
free of `TIME_WAIT` entries — the driver refuses to start otherwise):

```console
git checkout 6a49f0963c9d30a7866ebf5a413090a5fb4090b5
bench/scale/config-persistence/run-receipt.sh
```

Raw output is private and ignored under `target/config-persistence/`:
provenance, binary hashes, the config template, one log per daemon generation,
per-phase history and effective-config and Prometheus captures, the subject's
before and after neighbor JSON, `summary.json`, and checksums. It carries host
paths and is not published; the rows above are the sanitized result.
