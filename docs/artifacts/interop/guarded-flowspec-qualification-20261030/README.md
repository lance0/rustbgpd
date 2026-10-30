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
| Tree under test | parent `be5e4e5b4` plus the qualification test. The lab image's source-id is `d2e3b8aa4dab…`. The committed tree (`51fa81bd6206…`) differs only in a clippy fix to the in-process test helper. |
| Lab image | `rustbgpd:guarded-qual` (`docker build --target dev`), image `sha256:4855f2f3f263…`, checked with `scripts/source-id.sh --check` |
| Receiving peer | FRR 10.7.1, `quay.io/frrouting/frr@sha256:e995beaa50fd…` |
| Rollback target | `ghcr.io/lance0/rustbgpd:0.80.1`, `sha256:a7a6c4533ba0…`, revision `2fb2cbf276ea` |

## Harness

- **In process** (`crates/api/src/guarded_flowspec_qualification_tests.rs`,
  part of `cargo test -p rustbgpd-api`). Covers cases 2, 3, 4, 6 and 7. Each
  case runs the real `InjectionService` and `RibManager` on a paused clock;
  cases 2 and 3 also use a real HTTP/2 server and client over an in-memory
  pipe. Orderings come from handshakes: a relay hands the test each update
  queued for the RIB, and a gate holds a call before its handler. Time moves
  only by `tokio::time::advance`. The gate stands in for delay that reaches
  the handler late, not for delay on the wire.
- **Lab** (`tests/interop/scripts/qualify-guarded-flowspec-controller-loss.sh`).
  Covers case 5 on its own copy of the M22 topology (rustbgpd to FRR, plus a
  rustbgpd source). Lab times are wall clock on one host.
- **Rollback** (`tests/interop/scripts/qualify-guarded-flowspec-rollback.sh`).
  Covers case 1: the release image runs without peers and is driven by a
  grpcurl client using this tree's proto.

## Results

| Case | Bar | Legacy control | Result |
|---|---|---|---|
| 1 Rollback (0.80.1) | No guarded call is OK; leases and local rules (one pre-existing rule, named by the guarded delete) byte-identical | `AddLeasedFlowSpec` commits and changes the inventory | PASS: all four `UNIMPLEMENTED`, unchanged; control committed |
| 2 Queued past the client deadline | Window expired at commit: no rule, no lease. Window live: the rule commits and its revision reads back | Legacy add queued the same way commits | PASS |
| 3 Held before the handler | `WINDOW_NOT_LIVE`, nothing changes | Legacy add held the same way commits | PASS |
| 4 Delayed retry and renewal, three orders | No deadline past the latest window; the late retry revives nothing | Delayed `RenewLease` extends to arrival + 60 s; a late re-add starts a new generation | PASS |
| 5 Controller loss | Deadline ≤ `t_w`; local absence ≤ `t_w` + 2 s; FRR absence ≤ local + 5 s; session up | Late `RenewLease` keeps the legacy rule at FRR past its deadline | PASS (run `loss-4`) |
| 5 Ingest-stall control (S = 8 s) | 2 s ≤ local absence − `t_w` ≤ S + 5 s; FRR ≤ local + 5 s | As above | PASS (run `stall-3`) |
| 6 Foreign and stale mutations, sibling live | `OWNER_MISMATCH` and `REVISION_MISMATCH`; sibling and lease unchanged; late delete refused | Late legacy delete removes the newer admission | PASS |
| 7 Window cap | 65th window `RESOURCE_EXHAUSTED`; earlier window still admits; other owner unaffected; frees on expiry | Legacy adds unaffected | PASS |

Case 5 measurements, in seconds after `t_w`, the last window's expiry
bounded from below by the issue request's send time:

| Run | Lease deadline | Local absence (daemon log) | Local absence (first poll) | FRR absence after local | Legacy rule past its deadline |
|---|---|---|---|---|---|
| `loss-4` | +0.052 | +0.047 | +0.105 | +0.172 | 8.3 |
| `stall-3` | +0.052 | +7.069 | +15.077 | +0.285 | 23.2 |

The lease deadline is an upper bound taken from the lease listing after a
late 60 s guarded renewal. Uncapped, that renewal would land about 54 s past
`t_w`.

## Red proofs (in-process, each check removed once, then restored and checked with `cmp`)

- Window-liveness check in the lease table's admission removed: case 3 fails,
  `left: (Ok, "") right: (FailedPrecondition, "WINDOW_NOT_LIVE")`.
- Revision check on the guarded delete removed: case 6 fails,
  `left: [.., (Ok, ""), (Ok, "")] right: [.., (FailedPrecondition, "REVISION_MISMATCH") ×2]`.

## Failed and invalid runs, kept in `runs/`

- `rollback-1` INVALID: the harness config lacked `log_format`, which 0.80.1
  requires, so the daemon never started.
- `rollback-2` PASS, but against an empty inventory. It is superseded by
  `rollback-3`, which adds a pre-existing rule that the guarded delete names.
- `loss-1`: no verdicts. The shared test library enables errexit, and the
  driver exited on its first failing probe; the driver now disables it.
- `loss-2` legacy control INVALID: the late legacy renewal was scheduled
  after the legacy deadline. The renewals now run in deadline order.
- `loss-3` PASS under the earlier measurement, in which the first absent poll
  dates local absence.
- `stall-1` and `stall-2` FAIL: local absence +15.07 s against a 13 s bar.
  The daemon log of `stall-2` shows the withdrawal turn applied at +7.02 s
  (`lag_ms` 7024). The poll that saw the rule gone was answered only after a
  second stalled ingest turn. FRR was also polled only after that local poll.
  The driver now dates local absence from the daemon's withdrawal record,
  keeps the first absent poll as an upper bound, and polls FRR on its own.
  The bars are unchanged.

## Scope

Local wall-clock lab measurements on one host, one rule, one peer. A host
suspend stops the monotonic clock (ADR-0144 §6). Rule removal at FRR is not
traffic forwarding. Daemon death with GR or LLGR negotiated is not covered.
