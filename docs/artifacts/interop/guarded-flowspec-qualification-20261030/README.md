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
  probe reads present, absent or error; an error is retried until the bar's
  deadline, and a deadline reached on an error is INVALID. The late guarded
  renewal must succeed, and its reply is recorded. A failed rollback snapshot,
  before or after, ends the run INVALID before anything is compared.

## Results

| Case | Bar | Legacy control | Result |
|---|---|---|---|
| 1 Rollback (0.80.1) | No guarded call is OK; leases and local rules (one pre-existing rule, named by the guarded delete) byte-identical | `AddLeasedFlowSpec` commits and changes the inventory | PASS (`rollback-4`): all four `UNIMPLEMENTED`, unchanged; control committed |
| 2 Queued past the client deadline | Window expired at commit: no rule, no lease. Window live: the rule commits and its revision reads back | Legacy add queued the same way commits | PASS |
| 3 Held before the handler | `WINDOW_NOT_LIVE`, nothing changes | Legacy add held the same way commits | PASS |
| 4 Delayed retry and renewal, three orders | No deadline past the latest window; the late retry revives nothing | Delayed `RenewLease` extends to arrival + 60 s; a late re-add starts a new generation | PASS |
| 5 Controller loss | Deadline ≤ `t_w`; local absence ≤ `t_w` + 2 s; FRR absence ≤ local + 5 s; session up | Late `RenewLease` keeps the legacy rule at FRR past its deadline | PASS (`loss-6`) |
| 5 Ingest-stall control (S = 8 s) | 2 s ≤ local absence − `t_w` ≤ S + 5 s; FRR ≤ local + 5 s | As above | PASS (`stall-5`) |
| 6 Foreign and stale mutations, sibling live | `OWNER_MISMATCH` and `REVISION_MISMATCH`; sibling and lease unchanged; late delete refused | Late legacy delete removes the newer admission | PASS |
| 7 Window cap | 65th window `RESOURCE_EXHAUSTED`; earlier window still admits; other owner unaffected; frees on expiry | Legacy adds unaffected | PASS |

Case 5, seconds after `t_w` (the last window's expiry, bounded from below by
the issue request's send time). Neither run recorded a failed read.

| Run | Lease deadline | Local absence (daemon log) | Local absence (first poll) | FRR absence after local | Legacy rule past its deadline |
|---|---|---|---|---|---|
| `loss-6` | +0.052 | +0.047 | +0.195 | +0.337 | 8.5 |
| `stall-5` | +0.052 | +7.071 | +15.092 | +0.310 | 23.2 |

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
- `loss-red-late-renew-2` (`QUAL_FAULT=late-renew`, stale generation): the
  renewal's `FailedPrecondition` is recorded and `late_guarded_renew INVALID`
  ends the case.

## Other runs, kept in `runs/`

Runs labelled `SUPERSEDED` were produced before read-error handling. Their raw
logs show no hidden read failure: `rollback-3`'s before and after snapshots
are valid, identical listings; the late guarded renewals in `loss-4` and
`stall-3` succeeded (`leaseRemainingMs` 5988 and 5990); their local absence
comes from the daemon log. That driver did not record FRR read errors, so
their FRR absence is not evidence.

- `rollback-1` INVALID: the config lacked `log_format`, which 0.80.1 requires.
- `rollback-2` PASS against an empty inventory; `rollback-3` added the named rule.
- `loss-1` no verdicts: the test library's errexit stopped the driver.
- `loss-2` legacy control INVALID: the legacy renewal ran after its deadline.
- `loss-3` PASS with local absence dated by the first absent poll.
- `stall-1`, `stall-2` FAIL under that poll method (+15.07 s against 13 s): the
  absent poll was answered only after a second stalled ingest turn, while the
  daemon log shows the withdrawal applied at +7.02 s. Bars unchanged.
- `loss-5`, `stall-4` PASS and `loss-red-frr-read-1` INVALID with read-error
  handling; `loss-red-late-renew-1` INVALID but lost its events file, so the
  driver now saves events on every exit path.

## Scope

Local wall-clock lab measurements on one host, one rule, one peer. A host
suspend stops the monotonic clock (ADR-0144 §6). Rule removal at FRR is not
traffic forwarding. Daemon death with GR or LLGR negotiated is not covered.
