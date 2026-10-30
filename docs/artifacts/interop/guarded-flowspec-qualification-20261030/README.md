# Guarded FlowSpec contract qualification — 2026-10-30

This receipt qualifies the guarded FlowSpec mutation contract of
[ADR-0144](../../../adr/0144-guarded-flowspec-mutations.md) on one development
host. It covers rollback to a release without the methods, delay and timeout
orderings, delayed retry and renewal, controller loss, foreign refusals and
the window cap. Every case is paired with a negative control under the legacy
leased contract. This is functional control-plane evidence for an alpha
surface outside v1. It is not a forwarding, latency, scale or soak result, and
the lab drivers are local only: hosted CI does not run them.

## Identity

| Item | Value |
|---|---|
| Tree under test | The commit that adds this receipt. The lab image's source-id `51fa81bd6206…` matches it; the lab drivers are not build inputs. |
| Lab image | `rustbgpd:guarded-qual` (`docker build --target dev`), image `sha256:aba2bf2d164a…`, checked with `scripts/source-id.sh --check` |
| Receiving peer | FRR 10.7.1, `quay.io/frrouting/frr@sha256:e995beaa50fd…` |
| Rollback target | `ghcr.io/lance0/rustbgpd:0.80.1`, `sha256:a7a6c4533ba0…`, revision `2fb2cbf276ea` |

## Harness

- **In process** (`crates/api/src/guarded_flowspec_qualification_tests.rs`,
  part of `cargo test -p rustbgpd-api`). Covers cases 2, 3, 4, 6 and 7 on a
  paused clock with the real `InjectionService` and `RibManager`; cases 2 and 3
  also use a real HTTP/2 server and client over an in-memory pipe. Orderings
  come from handshakes: a relay hands the test each update queued for the RIB,
  and a gate holds a call before its handler (late arrival at the handler, not
  delay on the wire). Time moves only by `tokio::time::advance`.
- **Lab** (`tests/interop/scripts/qualify-guarded-flowspec-controller-loss.sh`).
  Covers case 5 on its own copy of the M22 topology (rustbgpd to FRR, plus a
  rustbgpd source). Lab times are wall clock on one host.
- **Rollback** (`tests/interop/scripts/qualify-guarded-flowspec-rollback.sh`).
  Covers case 1: the release image runs without peers and is driven by a
  grpcurl client using this tree's proto.
- **Failed reads** never count as absence or as an unchanged inventory. A
  probe reads present, absent or error. Each read is bounded by the time left
  to its deadline (grpcurl `-max-time`; `timeout` around `docker exec` and
  around vtysh inside FRR), and a read that runs out of time is an error.
  Errors are retried until the deadline, and a deadline reached on an error is
  INVALID. The late guarded renewal must succeed, and its reply is recorded. A
  failed rollback snapshot, before or after, ends the run INVALID before
  anything is compared.

## Results

| Case | Bar | Legacy control | Result |
|---|---|---|---|
| 1 Rollback (0.80.1) | No guarded call is OK; leases and local rules (one pre-existing rule, named by the guarded delete) byte-identical | `AddLeasedFlowSpec` commits and changes the lease listing and the rule listing, each compared on its own | PASS (`rollback-5`): all four `UNIMPLEMENTED`, unchanged; control committed |
| 2 Queued past the client deadline | Window expired at commit: no rule, no lease. Window live: the rule commits and its revision reads back | Legacy add queued the same way commits | PASS |
| 3 Held before the handler | `WINDOW_NOT_LIVE`, nothing changes | Legacy add held the same way commits | PASS |
| 4 Delayed retry and renewal, three orders | No deadline past the latest window; the late retry revives nothing | Delayed `RenewLease` extends to arrival + 60 s; a late re-add starts a new generation | PASS |
| 5 Controller loss | Deadline ≤ `t_w`; local absence ≤ `t_w` + 2 s; FRR absence ≤ local + 5 s; session up | Late `RenewLease` keeps the legacy rule at FRR past its deadline | PASS (`loss-7`) |
| 5 Ingest-stall control (S = 8 s) | 2 s ≤ local absence − `t_w` ≤ S + 5 s; FRR ≤ local + 5 s | As above | PASS (`stall-6`) |
| 6 Foreign and stale mutations, sibling live | `OWNER_MISMATCH` and `REVISION_MISMATCH`; sibling and lease unchanged; late delete refused | Late legacy delete removes the newer admission | PASS |
| 7 Window cap | 65th window `RESOURCE_EXHAUSTED`; earlier window still admits; other owner unaffected; frees on expiry | Legacy adds unaffected | PASS |

Case 5, seconds after `t_w` (the last window's expiry, bounded from below by
the issue request's send time). Neither run recorded a failed read.

| Run | Lease deadline | Local absence (daemon log) | Local absence (first poll) | FRR absence after local | Legacy rule past its deadline |
|---|---|---|---|---|---|
| `loss-7` | +0.053 | +0.045 | +0.186 | +0.297 | 8.4 |
| `stall-6` | +0.052 | +7.068 | +15.090 | +0.346 | 23.3 |

Local absence is dated from the daemon's log record of the withdrawal turn,
with the first absent poll as an upper bound. The lease deadline is an upper
bound read after a late 60 s guarded renewal, which uncapped would land about
54 s past `t_w`.

## Red proofs

- In process, each check removed once, then restored and checked with `cmp`:
  without the window-liveness check in lease admission, case 3 gets `Ok`
  instead of `WINDOW_NOT_LIVE`; without the revision check on the guarded
  delete, case 6 gets `Ok` twice instead of `REVISION_MISMATCH`.
- `rollback-red-after-read` (`QUAL_FAULT=after-read`, daemon stopped before
  the after-snapshot): `snapshot INVALID`, exit 2, nothing compared.
- `loss-red-frr-read-2` (`QUAL_FAULT=frr-read`, FRR paused while its absence is
  polled): 152 failed FRR reads, `frr_absence INVALID`. Local absence still
  PASS. The legacy control is also INVALID: the outage outlasted the renewed
  30 s legacy lease, and the daemon expired it as designed.
- `loss-red-frr-hang` (`QUAL_FAULT=frr-hang`, FRR's bgpd and watchfrr
  stopped with SIGSTOP, so reads block instead of failing): one blocked read,
  ended by its time bound 0.23 s after the polling deadline (`t_w` + 28 s),
  `frr_absence INVALID`; the run finished instead of hanging. The legacy
  control is INVALID for the same reason as above.
- `loss-red-late-renew-2` (`QUAL_FAULT=late-renew`, stale generation): the
  renewal's `FailedPrecondition` is recorded and `late_guarded_renew INVALID`
  ends the case.

## Other runs, kept in `runs/`

A `SUPERSEDED` file in a run gives the reason. Runs through `rollback-3`,
`loss-4` and `stall-3` predate read-error handling; their raw logs show no
hidden read failure (`rollback-3`'s snapshots are valid, identical listings;
the late guarded renewals in `loss-4` and `stall-3` succeeded with
`leaseRemainingMs` 5988 and 5990), but FRR read errors were not recorded.

- `rollback-1` INVALID: the config lacked `log_format`, which 0.80.1 requires.
- `rollback-2` PASS against an empty inventory; `rollback-3` added the named rule.
- `rollback-4` PASS, superseded: its control compared both listings together.
- `loss-1` no verdicts (the test library's errexit); `loss-2` legacy control
  INVALID (renewal after its deadline); `loss-3` PASS dated by first poll.
- `stall-1`, `stall-2` FAIL under the first-poll method (+15.07 s against
  13 s); the daemon log shows the withdrawal at +7.02 s. Bars unchanged.
- `loss-5`, `stall-4`, `loss-6`, `stall-5` PASS, superseded: no probe time
  bound. The red proofs other than `loss-red-frr-hang` also predate it; the
  paths they prove do not depend on it. `loss-red-frr-read-1` repeats `-2`;
  `loss-red-late-renew-1` lost its events file, now saved on every exit.

## Scope

Local wall-clock lab measurements on one host, one rule, one peer. A host
suspend stops the monotonic clock (ADR-0144 §6). Rule removal at FRR is not
traffic forwarding. Daemon death with GR or LLGR negotiated is not covered.
